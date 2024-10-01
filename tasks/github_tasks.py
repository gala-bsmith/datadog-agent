from __future__ import annotations

import os
import re
import sys
import time
from collections import Counter
from functools import lru_cache

from invoke.context import Context
from invoke.exceptions import Exit
from invoke.tasks import task

from tasks.libs.ciproviders.github_actions_tools import (
    download_artifacts,
    download_with_retry,
    follow_workflow_run,
    print_failed_jobs_logs,
    print_workflow_conclusion,
    trigger_macos_workflow,
)
from tasks.libs.common.color import color_message
from tasks.libs.common.constants import DEFAULT_BRANCH, DEFAULT_INTEGRATIONS_CORE_BRANCH
from tasks.libs.common.datadog_api import create_gauge, send_metrics
from tasks.libs.common.junit_upload_core import repack_macos_junit_tar
from tasks.libs.common.utils import get_git_pretty_ref
from tasks.libs.owners.parsing import read_owners
from tasks.libs.pipeline.notifications import GITHUB_SLACK_MAP
from tasks.release import _get_release_json_value

ALL_TEAMS = '@datadog/agent-all'


@lru_cache(maxsize=None)
def concurrency_key():
    current_ref = get_git_pretty_ref()

    # We want workflows to run to completion on the default branch and release branches
    if re.search(rf'^({DEFAULT_BRANCH}|\d+\.\d+\.x)$', current_ref):
        return None

    return current_ref


def _trigger_macos_workflow(release, destination=None, retry_download=0, retry_interval=0, **kwargs):
    github_action_ref = _get_release_json_value(f'{release}::MACOS_BUILD_VERSION')

    run = trigger_macos_workflow(
        github_action_ref=github_action_ref,
        concurrency_key=concurrency_key(),
        **kwargs,
    )

    workflow_conclusion, workflow_url = follow_workflow_run(run)

    if workflow_conclusion == "failure":
        print_failed_jobs_logs(run)

    print_workflow_conclusion(workflow_conclusion, workflow_url)

    if destination:
        download_with_retry(download_artifacts, run, destination, retry_download, retry_interval)

    return workflow_conclusion


@task
def trigger_macos(
    _,
    workflow_type="build",
    datadog_agent_ref=DEFAULT_BRANCH,
    release_version="nightly-a7",
    major_version="7",
    python_runtimes="3",
    destination=".",
    version_cache=None,
    retry_download=3,
    retry_interval=10,
    fast_tests=None,
    test_washer=False,
    integrations_core_ref=DEFAULT_INTEGRATIONS_CORE_BRANCH,
):
    if workflow_type == "build":
        conclusion = _trigger_macos_workflow(
            # Provide the release version to be able to fetch the associated
            # macos-build branch from release.json for all workflows...
            release_version,
            destination,
            retry_download,
            retry_interval,
            workflow_name="macos.yaml",
            datadog_agent_ref=datadog_agent_ref,
            # ... And provide the release version as a workflow input when needed
            release_version=release_version,
            major_version=major_version,
            python_runtimes=python_runtimes,
            # Send pipeline id and bucket branch so that the package version
            # can be constructed properly for nightlies.
            gitlab_pipeline_id=os.environ.get("CI_PIPELINE_ID", None),
            bucket_branch=os.environ.get("BUCKET_BRANCH", None),
            version_cache_file_content=version_cache,
            integrations_core_ref=integrations_core_ref,
        )
    elif workflow_type == "test":
        conclusion = _trigger_macos_workflow(
            release_version,
            destination,
            retry_download,
            retry_interval,
            workflow_name="test.yaml",
            datadog_agent_ref=datadog_agent_ref,
            python_runtimes=python_runtimes,
            version_cache_file_content=version_cache,
            fast_tests=fast_tests,
            test_washer=test_washer,
        )
        repack_macos_junit_tar(conclusion, "junit-tests_macos.tgz", "junit-tests_macos-repacked.tgz")
    elif workflow_type == "lint":
        conclusion = _trigger_macos_workflow(
            release_version,
            workflow_name="lint.yaml",
            datadog_agent_ref=datadog_agent_ref,
            python_runtimes=python_runtimes,
            version_cache_file_content=version_cache,
        )
    if conclusion != "success":
        raise Exit(message=f"Macos {workflow_type} workflow {conclusion}", code=1)


@task
def lint_codeowner(_):
    """
    Check every package in `pkg` has an owner
    """

    base = os.path.dirname(os.path.abspath(__file__))
    root_folder = os.path.join(base, "..")
    os.chdir(root_folder)

    owners = _get_code_owners(root_folder)

    # make sure each root package has an owner
    pkgs_without_owner = _find_packages_without_owner(owners, "pkg")
    if len(pkgs_without_owner) > 0:
        raise Exit(
            f'The following packages  in `pkg` directory don\'t have an owner in CODEOWNERS: {pkgs_without_owner}',
            code=1,
        )


def _find_packages_without_owner(owners, folder):
    pkg_without_owners = []
    for x in os.listdir(folder):
        path = os.path.join("/" + folder, x)
        if path not in owners:
            pkg_without_owners.append(path)
    return pkg_without_owners


def _get_code_owners(root_folder):
    code_owner_path = os.path.join(root_folder, ".github", "CODEOWNERS")
    owners = {}
    with open(code_owner_path) as f:
        for line in f:
            line = line.strip()
            line = line.split("#")[0]  # remove comment
            if len(line) > 0:
                parts = line.split()
                path = os.path.normpath(parts[0])
                # example /tools/retry_file_dump ['@DataDog/agent-metrics-logs']
                owners[path] = parts[1:]
    return owners


def _find_orphans_in_codeowner(owners):
    error = False

    for rule in owners.paths:
        # Get the static part of the rule path, removing matching subpath (such as '*')
        static_root = _get_static_root(rule[1])
        if not _is_pattern_in_fs(static_root, rule[0]):
            if not error:
                print(
                    color_message(
                        "The following rules are outdated: they don't point to existing file/directory", "red"
                    ),
                    file=sys.stderr,
                )
                error = True
            print(color_message(f"\t- {rule[1]}\t{rule[2]}", "orange"), file=sys.stderr)

    return error


def _get_static_root(pattern):
    result = "./"

    if not pattern.startswith("/"):
        # TODO
        return result

    # We remove the '\' anchor character from the path
    pattern = pattern[1:]

    for elem in pattern.split("/"):
        if '*' in elem:
            return result
        result = os.path.join(result, elem)
    return result


def _is_pattern_in_fs(path, pattern):
    """
    Checks if a given pattern matches any file within the specified path.

    Args:
        path (str): The file or directory path to search within.
        pattern (re.Pattern): The compiled regular expression pattern to match against file paths.

    Returns:
        bool: True if the pattern matches any file path within the specified path, False otherwise.
    """
    if os.path.isfile(path):
        return True
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for name in files:
                # file_path is the relative path from the root of the repo, without "./" at the begining
                file_path = os.path.join(root, name)[2:]

                # Check if the file path matches any of the regex patterns
                if pattern.match(file_path):
                    return True
    return False


@task
def get_milestone_id(_, milestone):
    # Local import as github isn't part of our default set of installed
    # dependencies, and we don't want to propagate it to files importing this one
    from tasks.libs.ciproviders.github_api import GithubAPI

    gh = GithubAPI()
    m = gh.get_milestone_by_name(milestone)
    if not m:
        raise Exit(f'Milestone {milestone} wasn\'t found in the repo', code=1)
    print(m.number)


@task
def send_rate_limit_info_datadog(_, pipeline_id, app_instance):
    from tasks.libs.ciproviders.github_api import GithubAPI

    gh = GithubAPI()
    rate_limit_info = gh.get_rate_limit_info()
    print(f"Remaining rate limit for app instance {app_instance}: {rate_limit_info[0]}/{rate_limit_info[1]}")
    metric = create_gauge(
        metric_name='github.rate_limit.remaining',
        timestamp=int(time.time()),
        value=rate_limit_info[0],
        tags=[
            'source:github',
            'repository:datadog-agent',
            f'app_instance:{app_instance}',
        ],
    )
    send_metrics([metric])


@task
def get_token_from_app(_, app_id_env='GITHUB_APP_ID', pkey_env='GITHUB_KEY_B64'):
    from .libs.ciproviders.github_api import GithubAPI

    GithubAPI.get_token_from_app(app_id_env, pkey_env)


def _get_teams(changed_files, owners_file='.github/CODEOWNERS') -> list[str]:
    codeowners = read_owners(owners_file)

    team_counter = Counter()
    for file in changed_files:
        owners = [name for (kind, name) in codeowners.of(file) if kind == 'TEAM']
        team_counter.update(owners)

    team_count = team_counter.most_common()
    if team_count == []:
        return []

    _, best_count = team_count[0]
    best_teams = [team.casefold() for (team, count) in team_count if count == best_count]

    return best_teams


def _get_team_labels():
    import toml

    with open('.ddqa/config.toml') as f:
        data = toml.loads(f.read())

    labels = []
    for team in data['teams'].values():
        labels.extend(team.get('github_labels', []))
    return labels


@task
def assign_team_label(_, pr_id=-1):
    """
    Assigns the github team label name if teams can
    be deduced from the changed files
    """
    from tasks.libs.ciproviders.github_api import GithubAPI

    gh = GithubAPI('DataDog/datadog-agent')

    labels = gh.get_pr_labels(pr_id)

    # Skip if necessary
    if 'qa/done' in labels or 'qa/no-code-change' in labels:
        print('Qa done or no code change, skipping')
        return

    if any(label.startswith('team/') for label in labels):
        print('This PR already has a team label, skipping')
        return

    # Find team
    teams = _get_teams(gh.get_pr_files(pr_id))
    if teams == []:
        print('No team found')
        return

    _assign_pr_team_labels(gh, pr_id, teams)


def _assign_pr_team_labels(gh, pr_id, teams):
    """
    Assign team labels (team/team-name) for each team (@datadog/team-name)
    """
    import github

    # Get labels
    all_team_labels = _get_team_labels()
    team_labels = [f"team{team.removeprefix('@datadog')}" for team in teams]

    # Assign label
    for label_name in team_labels:
        if label_name not in all_team_labels:
            print(label_name, 'cannot be found in .ddqa/config.toml, skipping')
        else:
            try:
                gh.add_pr_label(pr_id, label_name)
                print(label_name, 'label assigned to the pull request')
            except github.GithubException:
                print(f'Failed to assign label {label_name}')


@task
def handle_community_pr(_, repo='', pr_id=-1, labels=''):
    """
    Will set labels and notify teams about a newly opened community PR
    """
    from slack_sdk import WebClient

    from tasks.libs.ciproviders.github_api import GithubAPI

    # Get review teams / channels
    gh = GithubAPI()

    # Find teams corresponding to file changes
    teams = _get_teams(gh.get_pr_files(pr_id)) or [ALL_TEAMS]
    channels = [GITHUB_SLACK_MAP[team.lower()] for team in teams if team if team.lower() in GITHUB_SLACK_MAP]

    # Remove duplicates
    channels = list(set(channels))

    # Update labels
    for label in labels.split(','):
        if label:
            gh.add_pr_label(pr_id, label)

    if teams != [ALL_TEAMS]:
        _assign_pr_team_labels(gh, pr_id, teams)

    # Create message
    pr = gh.get_pr(pr_id)
    title = pr.title.strip()
    message = f':pr: *New Community PR*\n{title} <{pr.html_url}|{repo}#{pr_id}>'

    # Post message
    client = WebClient(os.environ['SLACK_API_TOKEN'])
    for channel in channels:
        client.chat_postMessage(channel=channel, text=message)


@task
def milestone_pr_team_stats(_: Context, milestone: str, team: str):
    """
    This task prints statistics about the PRs opened by a given team and
    merged in the given milestone.
    """
    from tasks.libs.ciproviders.github_api import GithubAPI

    gh = GithubAPI()
    team_members = gh.get_team_members(team)
    authors = ' '.join("author:" + member.login for member in team_members)
    common_query = f'repo:DataDog/datadog-agent is:pr is:merged milestone:{milestone} {authors}'

    no_code_changes_query = common_query + ' label:qa/no-code-change'
    no_code_changes = gh.search_issues(no_code_changes_query).totalCount

    qa_done_query = common_query + ' -label:qa/no-code-change label:qa/done'
    qa_done = gh.search_issues(qa_done_query).totalCount

    with_qa_query = common_query + ' -label:qa/no-code-change -label:qa/done'
    with_qa = gh.search_issues(with_qa_query).totalCount

    print("no code changes :", no_code_changes)
    print("qa done :", qa_done)
    print("with qa :", with_qa)
    print("proportion of PRs with code changes and QA done :", 100 * qa_done / (qa_done + with_qa), "%")


@task
def pr_commenter(
    _,
    title: str,
    body: str = '',
    pr_id: int | None = None,
    verbose: bool = True,
    delete: bool = False,
    force_delete: bool = False,
    echo: bool = False,
):
    """
    Will comment or update current comment posted on the PR with the new data.
    The title is used to identify the comment to update.

    - pr_id: If None, will use $CI_COMMIT_BRANCH to identify which PR to comment on.
    - delete: If True and the body is empty, will delete the comment.
    - force_delete: Won't throw error if the comment to delete is not found.
    - echo: Print comment content to stdout.

    Inspired by the pr-commenter binary from <https://github.com/DataDog/devtools>
    """

    from tasks.libs.ciproviders.github_api import GithubAPI

    if not body and not delete:
        return

    assert not delete or not body, "Use delete with an empty body to delete the comment"

    github = GithubAPI()

    if pr_id is None:
        branch = os.environ["CI_COMMIT_BRANCH"]
        prs = list(github.get_pr_for_branch(branch))
        assert len(prs) == 1, f"Expected 1 PR for branch {branch}, found {len(prs)} PRs"
        pr = prs[0]
    else:
        pr = github.get_pr(pr_id)

    # Created / updated / deleted comment
    action = ''
    header = f'## {title}'
    content = f'{header}\n\n{body}'

    comment = github.find_comment(pr, header)

    if comment:
        if delete:
            comment.delete()
            action = 'Deleted'
        else:
            comment.edit(content)
            action = 'Updated'
    else:
        if delete and force_delete:
            if verbose:
                print('Comment to delete not found, skipping')
            return
        else:
            assert not delete, 'Comment to delete not found'

        github.publish_comment(pr, content)
        action = 'Created'

    if echo:
        if verbose:
            print('Content:\n')
        print(content)
        print()

    if verbose:
        print(f"{action} comment on PR #{pr.number} - {pr.title}")
