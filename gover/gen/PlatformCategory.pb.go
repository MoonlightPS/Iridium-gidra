// Sorapointa - A server software re-implementation for a certain anime game, and avoid sorapointa.
// Copyright (C) 2022  Sorapointa Team
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
// 	protoc        v3.11.3
// source: PlatformCategory.proto

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

type PlatformCategory int32

const (
	PlatformCategory_PLATFORM_CATEGORY_NONE PlatformCategory = 0
	PlatformCategory_PLATFORM_CATEGORY_PCM  PlatformCategory = 1
	PlatformCategory_PLATFORM_CATEGORY_PSN  PlatformCategory = 2
)

// Enum value maps for PlatformCategory.
var (
	PlatformCategory_name = map[int32]string{
		0: "PLATFORM_CATEGORY_NONE",
		1: "PLATFORM_CATEGORY_PCM",
		2: "PLATFORM_CATEGORY_PSN",
	}
	PlatformCategory_value = map[string]int32{
		"PLATFORM_CATEGORY_NONE": 0,
		"PLATFORM_CATEGORY_PCM":  1,
		"PLATFORM_CATEGORY_PSN":  2,
	}
)

func (x PlatformCategory) Enum() *PlatformCategory {
	p := new(PlatformCategory)
	*p = x
	return p
}

func (x PlatformCategory) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (PlatformCategory) Descriptor() protoreflect.EnumDescriptor {
	return file_PlatformCategory_proto_enumTypes[0].Descriptor()
}

func (PlatformCategory) Type() protoreflect.EnumType {
	return &file_PlatformCategory_proto_enumTypes[0]
}

func (x PlatformCategory) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use PlatformCategory.Descriptor instead.
func (PlatformCategory) EnumDescriptor() ([]byte, []int) {
	return file_PlatformCategory_proto_rawDescGZIP(), []int{0}
}

var File_PlatformCategory_proto protoreflect.FileDescriptor

var file_PlatformCategory_proto_rawDesc = []byte{
	0x0a, 0x16, 0x50, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x43, 0x61, 0x74, 0x65, 0x67, 0x6f,
	0x72, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2a, 0x64, 0x0a, 0x10, 0x50, 0x6c, 0x61, 0x74,
	0x66, 0x6f, 0x72, 0x6d, 0x43, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x12, 0x1a, 0x0a, 0x16,
	0x50, 0x4c, 0x41, 0x54, 0x46, 0x4f, 0x52, 0x4d, 0x5f, 0x43, 0x41, 0x54, 0x45, 0x47, 0x4f, 0x52,
	0x59, 0x5f, 0x4e, 0x4f, 0x4e, 0x45, 0x10, 0x00, 0x12, 0x19, 0x0a, 0x15, 0x50, 0x4c, 0x41, 0x54,
	0x46, 0x4f, 0x52, 0x4d, 0x5f, 0x43, 0x41, 0x54, 0x45, 0x47, 0x4f, 0x52, 0x59, 0x5f, 0x50, 0x43,
	0x4d, 0x10, 0x01, 0x12, 0x19, 0x0a, 0x15, 0x50, 0x4c, 0x41, 0x54, 0x46, 0x4f, 0x52, 0x4d, 0x5f,
	0x43, 0x41, 0x54, 0x45, 0x47, 0x4f, 0x52, 0x59, 0x5f, 0x50, 0x53, 0x4e, 0x10, 0x02, 0x42, 0x06,
	0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_PlatformCategory_proto_rawDescOnce sync.Once
	file_PlatformCategory_proto_rawDescData = file_PlatformCategory_proto_rawDesc
)

func file_PlatformCategory_proto_rawDescGZIP() []byte {
	file_PlatformCategory_proto_rawDescOnce.Do(func() {
		file_PlatformCategory_proto_rawDescData = protoimpl.X.CompressGZIP(file_PlatformCategory_proto_rawDescData)
	})
	return file_PlatformCategory_proto_rawDescData
}

var file_PlatformCategory_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_PlatformCategory_proto_goTypes = []interface{}{
	(PlatformCategory)(0), // 0: PlatformCategory
}
var file_PlatformCategory_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_PlatformCategory_proto_init() }
func file_PlatformCategory_proto_init() {
	if File_PlatformCategory_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_PlatformCategory_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_PlatformCategory_proto_goTypes,
		DependencyIndexes: file_PlatformCategory_proto_depIdxs,
		EnumInfos:         file_PlatformCategory_proto_enumTypes,
	}.Build()
	File_PlatformCategory_proto = out.File
	file_PlatformCategory_proto_rawDesc = nil
	file_PlatformCategory_proto_goTypes = nil
	file_PlatformCategory_proto_depIdxs = nil
}
