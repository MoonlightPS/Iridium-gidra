// https://github.com/SlushinPS/beach-simulator
// Copyright (C) 2023 Slushy Team
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.5
// source: FICAFCEJKPF.proto

package gen

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type FICAFCEJKPF int32

const (
	FICAFCEJKPF_FICAFCEJKPF_GcgPerformInvalid      FICAFCEJKPF = 0
	FICAFCEJKPF_FICAFCEJKPF_GcgPerformCardExchange FICAFCEJKPF = 1
	FICAFCEJKPF_FICAFCEJKPF_GcgPerformFirstHand    FICAFCEJKPF = 2
	FICAFCEJKPF_FICAFCEJKPF_GcgPerformReroll       FICAFCEJKPF = 3
	FICAFCEJKPF_FICAFCEJKPF_GcgPreformCostRevise   FICAFCEJKPF = 4
	FICAFCEJKPF_FICAFCEJKPF_GcgPerformRedraw       FICAFCEJKPF = 5
	FICAFCEJKPF_FICAFCEJKPF_GcgPerformHistory      FICAFCEJKPF = 6
)

// Enum value maps for FICAFCEJKPF.
var (
	FICAFCEJKPF_name = map[int32]string{
		0: "FICAFCEJKPF_GcgPerformInvalid",
		1: "FICAFCEJKPF_GcgPerformCardExchange",
		2: "FICAFCEJKPF_GcgPerformFirstHand",
		3: "FICAFCEJKPF_GcgPerformReroll",
		4: "FICAFCEJKPF_GcgPreformCostRevise",
		5: "FICAFCEJKPF_GcgPerformRedraw",
		6: "FICAFCEJKPF_GcgPerformHistory",
	}
	FICAFCEJKPF_value = map[string]int32{
		"FICAFCEJKPF_GcgPerformInvalid":      0,
		"FICAFCEJKPF_GcgPerformCardExchange": 1,
		"FICAFCEJKPF_GcgPerformFirstHand":    2,
		"FICAFCEJKPF_GcgPerformReroll":       3,
		"FICAFCEJKPF_GcgPreformCostRevise":   4,
		"FICAFCEJKPF_GcgPerformRedraw":       5,
		"FICAFCEJKPF_GcgPerformHistory":      6,
	}
)

func (x FICAFCEJKPF) Enum() *FICAFCEJKPF {
	p := new(FICAFCEJKPF)
	*p = x
	return p
}

func (x FICAFCEJKPF) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (FICAFCEJKPF) Descriptor() protoreflect.EnumDescriptor {
	return file_FICAFCEJKPF_proto_enumTypes[0].Descriptor()
}

func (FICAFCEJKPF) Type() protoreflect.EnumType {
	return &file_FICAFCEJKPF_proto_enumTypes[0]
}

func (x FICAFCEJKPF) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use FICAFCEJKPF.Descriptor instead.
func (FICAFCEJKPF) EnumDescriptor() ([]byte, []int) {
	return file_FICAFCEJKPF_proto_rawDescGZIP(), []int{0}
}

var File_FICAFCEJKPF_proto protoreflect.FileDescriptor

var file_FICAFCEJKPF_proto_rawDesc = []byte{
	0x0a, 0x11, 0x46, 0x49, 0x43, 0x41, 0x46, 0x43, 0x45, 0x4a, 0x4b, 0x50, 0x46, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2a, 0x8a, 0x02, 0x0a, 0x0b, 0x46, 0x49, 0x43, 0x41, 0x46, 0x43, 0x45, 0x4a,
	0x4b, 0x50, 0x46, 0x12, 0x21, 0x0a, 0x1d, 0x46, 0x49, 0x43, 0x41, 0x46, 0x43, 0x45, 0x4a, 0x4b,
	0x50, 0x46, 0x5f, 0x47, 0x63, 0x67, 0x50, 0x65, 0x72, 0x66, 0x6f, 0x72, 0x6d, 0x49, 0x6e, 0x76,
	0x61, 0x6c, 0x69, 0x64, 0x10, 0x00, 0x12, 0x26, 0x0a, 0x22, 0x46, 0x49, 0x43, 0x41, 0x46, 0x43,
	0x45, 0x4a, 0x4b, 0x50, 0x46, 0x5f, 0x47, 0x63, 0x67, 0x50, 0x65, 0x72, 0x66, 0x6f, 0x72, 0x6d,
	0x43, 0x61, 0x72, 0x64, 0x45, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x10, 0x01, 0x12, 0x23,
	0x0a, 0x1f, 0x46, 0x49, 0x43, 0x41, 0x46, 0x43, 0x45, 0x4a, 0x4b, 0x50, 0x46, 0x5f, 0x47, 0x63,
	0x67, 0x50, 0x65, 0x72, 0x66, 0x6f, 0x72, 0x6d, 0x46, 0x69, 0x72, 0x73, 0x74, 0x48, 0x61, 0x6e,
	0x64, 0x10, 0x02, 0x12, 0x20, 0x0a, 0x1c, 0x46, 0x49, 0x43, 0x41, 0x46, 0x43, 0x45, 0x4a, 0x4b,
	0x50, 0x46, 0x5f, 0x47, 0x63, 0x67, 0x50, 0x65, 0x72, 0x66, 0x6f, 0x72, 0x6d, 0x52, 0x65, 0x72,
	0x6f, 0x6c, 0x6c, 0x10, 0x03, 0x12, 0x24, 0x0a, 0x20, 0x46, 0x49, 0x43, 0x41, 0x46, 0x43, 0x45,
	0x4a, 0x4b, 0x50, 0x46, 0x5f, 0x47, 0x63, 0x67, 0x50, 0x72, 0x65, 0x66, 0x6f, 0x72, 0x6d, 0x43,
	0x6f, 0x73, 0x74, 0x52, 0x65, 0x76, 0x69, 0x73, 0x65, 0x10, 0x04, 0x12, 0x20, 0x0a, 0x1c, 0x46,
	0x49, 0x43, 0x41, 0x46, 0x43, 0x45, 0x4a, 0x4b, 0x50, 0x46, 0x5f, 0x47, 0x63, 0x67, 0x50, 0x65,
	0x72, 0x66, 0x6f, 0x72, 0x6d, 0x52, 0x65, 0x64, 0x72, 0x61, 0x77, 0x10, 0x05, 0x12, 0x21, 0x0a,
	0x1d, 0x46, 0x49, 0x43, 0x41, 0x46, 0x43, 0x45, 0x4a, 0x4b, 0x50, 0x46, 0x5f, 0x47, 0x63, 0x67,
	0x50, 0x65, 0x72, 0x66, 0x6f, 0x72, 0x6d, 0x48, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x10, 0x06,
	0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_FICAFCEJKPF_proto_rawDescOnce sync.Once
	file_FICAFCEJKPF_proto_rawDescData = file_FICAFCEJKPF_proto_rawDesc
)

func file_FICAFCEJKPF_proto_rawDescGZIP() []byte {
	file_FICAFCEJKPF_proto_rawDescOnce.Do(func() {
		file_FICAFCEJKPF_proto_rawDescData = protoimpl.X.CompressGZIP(file_FICAFCEJKPF_proto_rawDescData)
	})
	return file_FICAFCEJKPF_proto_rawDescData
}

var file_FICAFCEJKPF_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_FICAFCEJKPF_proto_goTypes = []interface{}{
	(FICAFCEJKPF)(0), // 0: FICAFCEJKPF
}
var file_FICAFCEJKPF_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_FICAFCEJKPF_proto_init() }
func file_FICAFCEJKPF_proto_init() {
	if File_FICAFCEJKPF_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_FICAFCEJKPF_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_FICAFCEJKPF_proto_goTypes,
		DependencyIndexes: file_FICAFCEJKPF_proto_depIdxs,
		EnumInfos:         file_FICAFCEJKPF_proto_enumTypes,
	}.Build()
	File_FICAFCEJKPF_proto = out.File
	file_FICAFCEJKPF_proto_rawDesc = nil
	file_FICAFCEJKPF_proto_goTypes = nil
	file_FICAFCEJKPF_proto_depIdxs = nil
}
