// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package diconfig

import (
	"reflect"
	"strings"

	"github.com/DataDog/datadog-agent/pkg/dynamicinstrumentation/ditypes"
)

// GenerateLocationExpression takes metadata about a parameter, including its type and location, and generates a list of
// LocationExpressions that can be used to read the parameter from the target process.
//
// It walks the tree of the parameter and its pieces, generating LocationExpressions for each piece.
// The following logic is applied:
func GenerateLocationExpression(param *ditypes.Parameter) {
	triePaths, expressionTargets := generateLocationVisitsMap(param)
	for pathToInstrumentationTarget, instrumentationTarget := range expressionTargets {
		pathElements := []string{pathToInstrumentationTarget}
		// pathElements gets populated with every individual stretch of the path to the instrumentationTarget
		for {
			lastElementIndex := strings.LastIndex(pathToInstrumentationTarget, "@")
			if lastElementIndex == -1 {
				break
			}
			pathToInstrumentationTarget = pathToInstrumentationTarget[:lastElementIndex]
			pathElements = append([]string{pathToInstrumentationTarget}, pathElements...)
		}

		// Go through each path element of the instrumentation target
		for i := range pathElements {
			elementParam, ok := triePaths[pathElements[i]]
			if !ok {
				continue
			}

			// Check if this instrumentation target is directly assigned
			if elementParam.Location != nil {
				// This element is directly assigned

				if elementParam.Kind == uint(reflect.Array) {
					//TODO
				}

				elementParam.LocationExpressions = append(elementParam.LocationExpressions, ditypes.DirectReadLocationExpression(elementParam))
				if elementParam.Kind != uint(reflect.Pointer) {
					// Since this isn't a pointer, we can just directly read
					elementParam.LocationExpressions = append(elementParam.LocationExpressions, ditypes.PopLocationExpression(1, uint(elementParam.TotalSize)))
				}
				continue
			} else {
				// This is not directly assigned, expect the address for it on the stack
				if elementParam.Kind == uint(reflect.Pointer) {
					elementParam.LocationExpressions = append(elementParam.LocationExpressions,
						ditypes.DirectReadLocationExpression(elementParam),
					)
					if len(elementParam.ParameterPieces) > 0 &&
						(elementParam.ParameterPieces[0].Kind == uint(reflect.String) ||
							elementParam.ParameterPieces[0].Kind == uint(reflect.Slice)) {
						// In the special case of pointers to strings and slices, we need the address pushed twice
						// to the stack for the sake of parsing both relevant fields (len/ptr).
						elementParam.LocationExpressions = append(elementParam.LocationExpressions,
							ditypes.DirectReadLocationExpression(elementParam),
						)
					}
				} else if elementParam.Kind == uint(reflect.Struct) {
					// Structs don't provide context on location, or have values themselves
					continue
				} else if elementParam.Kind == uint(reflect.String) {
					if len(instrumentationTarget.ParameterPieces) != 2 {
						continue
					}
					str := instrumentationTarget.ParameterPieces[0]
					len := instrumentationTarget.ParameterPieces[1]
					if str.Location != nil && len.Location != nil {
						// Fields of the string are directly assigned
						elementParam.LocationExpressions = append(elementParam.LocationExpressions,
							ditypes.DirectReadLocationExpression(&str),
							ditypes.DirectReadLocationExpression(&len),
							ditypes.DereferenceDynamicToOutputLocationExpression(32, 1), //FIXME: use actual limit
						)
					} else {
						// Expect address of the string struct itself on the location expression stack
						elementParam.LocationExpressions = append(elementParam.LocationExpressions,
							ditypes.DereferenceLocationExpression(8),         // Put the char pointer onto the stack
							ditypes.DereferenceToOutputLocationExpression(3), // FIXME: this hardcodes string at 3 bytes
						)
					}
					continue
				} else if elementParam.Kind == uint(reflect.Slice) {
					if len(elementParam.ParameterPieces) != 3 {
						continue
					}

					// For each element in the slice:
					// - Read the pointer to the array onto the stack
					// - Add offset equal to (i*slice_element_size)  ( i is loop for the 0:max_slice_length )
					// - Append the expressions for reading the kind of element, which expect the address of it on the stack

					ptr := elementParam.ParameterPieces[0]
					len := elementParam.ParameterPieces[1]
					sliceElementType := ptr.ParameterPieces[0]

					// Generate and collect the location expressions for collecting an individual
					// element of this slice
					GenerateLocationExpression(&ptr.ParameterPieces[0])
					expressionsToUseForEachSliceElement := collectAndRemoveLocationExpressions(&ptr.ParameterPieces[0])

					// TODO: Need a way to short circuit slices:
					// - instruction in between each element that reads the slice length and compares it to current
					//   instruction being read (i.e. pass in `i`)

					if ptr.Location != nil && len.Location != nil {
						// Fields of the slice are directly assigned
						for i := 0; i < 3; i++ { //FIXME: replace 3 with actual max collection length
							elementParam.LocationExpressions = append(elementParam.LocationExpressions,
								ditypes.DirectReadLocationExpression(&ptr),
								ditypes.ApplyOffsetLocationExpression(uint(sliceElementType.TotalSize)*uint(i)),
							)
							elementParam.LocationExpressions = append(elementParam.LocationExpressions, expressionsToUseForEachSliceElement...)
						}
					} else {
						// Expect address on stack, use offsets accordingly
						elementParam.LocationExpressions = append(elementParam.LocationExpressions,
							ditypes.DereferenceLocationExpression(8), // Put the array pointer onto the stack
						)

						for i := 0; i < 3; i++ { //FIXME: replace 3 with actual max collection length
							elementParam.LocationExpressions = append(elementParam.LocationExpressions,
								ditypes.CopyLocationExpression(),
								ditypes.ApplyOffsetLocationExpression(uint(i*(int(sliceElementType.TotalSize)))),
							)
							elementParam.LocationExpressions = append(elementParam.LocationExpressions, expressionsToUseForEachSliceElement...)
						}
					}
					continue
				} else {
					elementParam.LocationExpressions = append(elementParam.LocationExpressions, ditypes.ApplyOffsetLocationExpression(uint(elementParam.FieldOffset)), ditypes.DereferenceToOutputLocationExpression(uint(elementParam.TotalSize)))
				}
			}
		}
	}
}

// collectAndRemoveLocationExpressions goes through the parameter tree (param.ParameterPieces) via
// depth first traversal, collecting the LocationExpression's from each parameter and appending them
// to a collective slice. As it collects the location expressions, it removes them from that parameter.
func collectAndRemoveLocationExpressions(param *ditypes.Parameter) []ditypes.LocationExpression {
	collectedExpressions := []ditypes.LocationExpression{}
	queue := []*ditypes.Parameter{param}
	var top *ditypes.Parameter

	for {
		if len(queue) == 0 {
			break
		}
		top = queue[0]
		queue = queue[1:]
		for i := range top.ParameterPieces {
			queue = append(queue, &top.ParameterPieces[i])
		}
		if len(top.LocationExpressions) > 0 {
			collectedExpressions = append(top.LocationExpressions, collectedExpressions...)
			top.LocationExpressions = []ditypes.LocationExpression{}
		}
	}
	return collectedExpressions
}

// generateLocationVisitsMap follows the tree of parameters (parameter.ParameterPieces), and
// collects string values of all the paths to nodes that need expressions (`needsExpressions`),
// as well as all combinations of elements that can be achieved by walking the tree (`trieKeys`).
func generateLocationVisitsMap(parameter *ditypes.Parameter) (trieKeys map[string]*ditypes.Parameter, needsExpressions map[string]*ditypes.Parameter) {
	trieKeys = map[string]*ditypes.Parameter{}
	needsExpressions = map[string]*ditypes.Parameter{}

	var visit func(param *ditypes.Parameter, path string)
	visit = func(param *ditypes.Parameter, path string) {
		trieKeys[path+param.Type] = param

		if len(param.ParameterPieces) == 0 ||
			isBasicType(param.Kind) ||
			param.Kind == uint(reflect.Array) ||
			param.Kind == uint(reflect.Slice) {
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

/*
	shallowCopy := make([]Person, len(original))
	copy(shallowCopy, original)
*/
