// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package diconfig

import (
	"math/rand"
	"reflect"
	"strings"

	"github.com/DataDog/datadog-agent/pkg/dynamicinstrumentation/ditypes"
	"github.com/kr/pretty"
)

// GenerateLocationExpression takes metadata about a parameter, including its type and location, and generates a list of
// LocationExpressions that can be used to read the parameter from the target process.
//
// It walks the tree of the parameter and its pieces, generating LocationExpressions for each piece.
// The following logic is applied:
func GenerateLocationExpression(parameter *ditypes.Parameter) {
	m, expressionTargets := generateLocationVisitsMap(parameter)
	pretty.Log("All:\n", m)
	pretty.Log("Needs expressions:\n", expressionTargets)

	for target, parameter := range expressionTargets {
		expressions := []ditypes.LocationExpression{}
		pathElements := []string{target}
		for {
			lastElementIndex := strings.LastIndex(target, "@")
			if lastElementIndex == -1 {
				break
			}
			target = target[:lastElementIndex]
			pathElements = append([]string{target}, pathElements...)
		}

		for i := range pathElements {
			elementParam, ok := m[pathElements[i]]
			if !ok {
				continue
			}
			// Check if this instrumentation target is directly assigned
			if elementParam.Location != nil {
				expressions = append(expressions, ditypes.DirectReadLocationExpression(elementParam))
				if elementParam.Kind != uint(reflect.Pointer) {
					// Since this isn't a pointer, we can just directly read
					expressions = append(expressions, ditypes.PopLocationExpression(1, uint(elementParam.TotalSize)))
				}
				continue
			} else {
				// This is not directly assigned, expect the address for it on the stack
				if elementParam.Kind == uint(reflect.Pointer) {
					expressions = append(expressions,
						ditypes.DirectReadLocationExpression(elementParam),
					)
					if len(elementParam.ParameterPieces) > 0 &&
						(elementParam.ParameterPieces[0].Kind == uint(reflect.String) ||
							elementParam.ParameterPieces[0].Kind == uint(reflect.Slice)) {
						// In the special case of pointers to strings and slices, we need the address pushed twice
						// to the stack for the sake of parsing both relevant fields (len/ptr).
						expressions = append(expressions,
							ditypes.DirectReadLocationExpression(elementParam),
						)
					}
				} else if elementParam.Kind == uint(reflect.Struct) {
					// Structs don't provide context on location, or have values themselves
					continue
				} else if elementParam.Kind == uint(reflect.String) {
					if len(parameter.ParameterPieces) != 2 {
						continue
					}
					str := parameter.ParameterPieces[0]
					len := parameter.ParameterPieces[1]
					if str.Location != nil && len.Location != nil {
						// Fields of the string are directly assigned
						expressions = append(expressions,
							ditypes.DirectReadLocationExpression(&str),
							ditypes.DirectReadLocationExpression(&len),
							ditypes.DereferenceDynamicToOutputLocationExpression(32, 1), //TODO: use actual limit
						)
					} else {
						// Expect address on stack, use offsets accordingly
						expressions = append(expressions,
							ditypes.ApplyOffsetLocationExpression(uint(len.FieldOffset)),
							ditypes.DereferenceLocationExpression(uint(len.TotalSize)),
							ditypes.DereferenceDynamicToOutputLocationExpression(32, 1),
						)
					}
					continue
				} else {
					expressions = append(expressions, ditypes.ApplyOffsetLocationExpression(uint(elementParam.FieldOffset)), ditypes.DereferenceToOutputLocationExpression(uint(elementParam.TotalSize)))
				}
			}
		}
		parameter.LocationExpressions = expressions
		pretty.Log("Produced expressions:", parameter.LocationExpressions)
	}
}

// - Can read address of pointers twice so the address stays on stack.
// - At the end of programs have an instruction for popping remainder of stack
// - Probably makes sense to set locations from parent parameter while going through pieces, then
//   calling the recursive function on the pieces

// generateLocationVisitsMap follows the tree of parameters (parameter.ParameterPieces), and
// collects string values of all the paths to leaf nodes, and sets it in returned map pointing
// to the location of that leaf node. The string values are a concatanation of the Type fields
// of all the parameters in the path.
func generateLocationVisitsMap(parameter *ditypes.Parameter) (map[string]*ditypes.Parameter, map[string]*ditypes.Parameter) {
	trieKeys := map[string]*ditypes.Parameter{}
	needsExpressions := map[string]*ditypes.Parameter{}

	var visit func(param *ditypes.Parameter, path string)
	visit = func(param *ditypes.Parameter, path string) {
		trieKeys[path+param.Type] = param

		if len(param.ParameterPieces) == 0 ||
			isBasicType(param.Kind) ||
			param.Kind == uint(reflect.Array) {
			needsExpressions[path+param.Type] = param
			return
		}

		for i := range param.ParameterPieces {
			newPath := path + param.Type + "@"
			visit(&param.ParameterPieces[i], newPath)
		}
	}
	visit(parameter, "")
	return trieKeys, needsExpressions
}

func isBasicType(kind uint) bool {
	switch reflect.Kind(kind) {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.String:
		return true
	default:
		return false
	}
}

func randomID() string {
	length := 6
	randomString := make([]byte, length)
	for i := 0; i < length; i++ {
		randomString[i] = byte(65 + rand.Intn(25))
	}
	return string(randomString)
}

/*
	shallowCopy := make([]Person, len(original))
	copy(shallowCopy, original)
*/
