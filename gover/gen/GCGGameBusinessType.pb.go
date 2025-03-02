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
// source: GCGGameBusinessType.proto

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

type GCGGameBusinessType int32

const (
	GCGGameBusinessType_GCG_GAME_BUSINESS_TYPE_NONE             GCGGameBusinessType = 0
	GCGGameBusinessType_GCG_GAME_BUSINESS_TYPE_GM               GCGGameBusinessType = 1
	GCGGameBusinessType_GCG_GAME_BUSINESS_TYPE_MATCH            GCGGameBusinessType = 2
	GCGGameBusinessType_GCG_GAME_BUSINESS_TYPE_PVP              GCGGameBusinessType = 3
	GCGGameBusinessType_GCG_GAME_BUSINESS_TYPE_TAVERN_CHALLENGE GCGGameBusinessType = 4
	GCGGameBusinessType_GCG_GAME_BUSINESS_TYPE_CONST_CHALLENGE  GCGGameBusinessType = 5
	GCGGameBusinessType_GCG_GAME_BUSINESS_TYPE_WORLD_CHALLENGE  GCGGameBusinessType = 6
	GCGGameBusinessType_GCG_GAME_BUSINESS_TYPE_BOSS_CHALLENGE   GCGGameBusinessType = 7
	GCGGameBusinessType_GCG_GAME_BUSINESS_TYPE_WEEK_CHALLENGE   GCGGameBusinessType = 8
	GCGGameBusinessType_GCG_GAME_BUSINESS_TYPE_BREAK_CHALLENGE  GCGGameBusinessType = 9
	GCGGameBusinessType_GCG_GAME_BUSINESS_TYPE_QUEST            GCGGameBusinessType = 10
	GCGGameBusinessType_GCG_GAME_BUSINESS_TYPE_GUIDE_GROUP      GCGGameBusinessType = 11
)

// Enum value maps for GCGGameBusinessType.
var (
	GCGGameBusinessType_name = map[int32]string{
		0:  "GCG_GAME_BUSINESS_TYPE_NONE",
		1:  "GCG_GAME_BUSINESS_TYPE_GM",
		2:  "GCG_GAME_BUSINESS_TYPE_MATCH",
		3:  "GCG_GAME_BUSINESS_TYPE_PVP",
		4:  "GCG_GAME_BUSINESS_TYPE_TAVERN_CHALLENGE",
		5:  "GCG_GAME_BUSINESS_TYPE_CONST_CHALLENGE",
		6:  "GCG_GAME_BUSINESS_TYPE_WORLD_CHALLENGE",
		7:  "GCG_GAME_BUSINESS_TYPE_BOSS_CHALLENGE",
		8:  "GCG_GAME_BUSINESS_TYPE_WEEK_CHALLENGE",
		9:  "GCG_GAME_BUSINESS_TYPE_BREAK_CHALLENGE",
		10: "GCG_GAME_BUSINESS_TYPE_QUEST",
		11: "GCG_GAME_BUSINESS_TYPE_GUIDE_GROUP",
	}
	GCGGameBusinessType_value = map[string]int32{
		"GCG_GAME_BUSINESS_TYPE_NONE":             0,
		"GCG_GAME_BUSINESS_TYPE_GM":               1,
		"GCG_GAME_BUSINESS_TYPE_MATCH":            2,
		"GCG_GAME_BUSINESS_TYPE_PVP":              3,
		"GCG_GAME_BUSINESS_TYPE_TAVERN_CHALLENGE": 4,
		"GCG_GAME_BUSINESS_TYPE_CONST_CHALLENGE":  5,
		"GCG_GAME_BUSINESS_TYPE_WORLD_CHALLENGE":  6,
		"GCG_GAME_BUSINESS_TYPE_BOSS_CHALLENGE":   7,
		"GCG_GAME_BUSINESS_TYPE_WEEK_CHALLENGE":   8,
		"GCG_GAME_BUSINESS_TYPE_BREAK_CHALLENGE":  9,
		"GCG_GAME_BUSINESS_TYPE_QUEST":            10,
		"GCG_GAME_BUSINESS_TYPE_GUIDE_GROUP":      11,
	}
)

func (x GCGGameBusinessType) Enum() *GCGGameBusinessType {
	p := new(GCGGameBusinessType)
	*p = x
	return p
}

func (x GCGGameBusinessType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (GCGGameBusinessType) Descriptor() protoreflect.EnumDescriptor {
	return file_GCGGameBusinessType_proto_enumTypes[0].Descriptor()
}

func (GCGGameBusinessType) Type() protoreflect.EnumType {
	return &file_GCGGameBusinessType_proto_enumTypes[0]
}

func (x GCGGameBusinessType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use GCGGameBusinessType.Descriptor instead.
func (GCGGameBusinessType) EnumDescriptor() ([]byte, []int) {
	return file_GCGGameBusinessType_proto_rawDescGZIP(), []int{0}
}

var File_GCGGameBusinessType_proto protoreflect.FileDescriptor

var file_GCGGameBusinessType_proto_rawDesc = []byte{
	0x0a, 0x19, 0x47, 0x43, 0x47, 0x47, 0x61, 0x6d, 0x65, 0x42, 0x75, 0x73, 0x69, 0x6e, 0x65, 0x73,
	0x73, 0x54, 0x79, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2a, 0xe8, 0x03, 0x0a, 0x13,
	0x47, 0x43, 0x47, 0x47, 0x61, 0x6d, 0x65, 0x42, 0x75, 0x73, 0x69, 0x6e, 0x65, 0x73, 0x73, 0x54,
	0x79, 0x70, 0x65, 0x12, 0x1f, 0x0a, 0x1b, 0x47, 0x43, 0x47, 0x5f, 0x47, 0x41, 0x4d, 0x45, 0x5f,
	0x42, 0x55, 0x53, 0x49, 0x4e, 0x45, 0x53, 0x53, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x4e, 0x4f,
	0x4e, 0x45, 0x10, 0x00, 0x12, 0x1d, 0x0a, 0x19, 0x47, 0x43, 0x47, 0x5f, 0x47, 0x41, 0x4d, 0x45,
	0x5f, 0x42, 0x55, 0x53, 0x49, 0x4e, 0x45, 0x53, 0x53, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x47,
	0x4d, 0x10, 0x01, 0x12, 0x20, 0x0a, 0x1c, 0x47, 0x43, 0x47, 0x5f, 0x47, 0x41, 0x4d, 0x45, 0x5f,
	0x42, 0x55, 0x53, 0x49, 0x4e, 0x45, 0x53, 0x53, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x4d, 0x41,
	0x54, 0x43, 0x48, 0x10, 0x02, 0x12, 0x1e, 0x0a, 0x1a, 0x47, 0x43, 0x47, 0x5f, 0x47, 0x41, 0x4d,
	0x45, 0x5f, 0x42, 0x55, 0x53, 0x49, 0x4e, 0x45, 0x53, 0x53, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f,
	0x50, 0x56, 0x50, 0x10, 0x03, 0x12, 0x2b, 0x0a, 0x27, 0x47, 0x43, 0x47, 0x5f, 0x47, 0x41, 0x4d,
	0x45, 0x5f, 0x42, 0x55, 0x53, 0x49, 0x4e, 0x45, 0x53, 0x53, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f,
	0x54, 0x41, 0x56, 0x45, 0x52, 0x4e, 0x5f, 0x43, 0x48, 0x41, 0x4c, 0x4c, 0x45, 0x4e, 0x47, 0x45,
	0x10, 0x04, 0x12, 0x2a, 0x0a, 0x26, 0x47, 0x43, 0x47, 0x5f, 0x47, 0x41, 0x4d, 0x45, 0x5f, 0x42,
	0x55, 0x53, 0x49, 0x4e, 0x45, 0x53, 0x53, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x43, 0x4f, 0x4e,
	0x53, 0x54, 0x5f, 0x43, 0x48, 0x41, 0x4c, 0x4c, 0x45, 0x4e, 0x47, 0x45, 0x10, 0x05, 0x12, 0x2a,
	0x0a, 0x26, 0x47, 0x43, 0x47, 0x5f, 0x47, 0x41, 0x4d, 0x45, 0x5f, 0x42, 0x55, 0x53, 0x49, 0x4e,
	0x45, 0x53, 0x53, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x57, 0x4f, 0x52, 0x4c, 0x44, 0x5f, 0x43,
	0x48, 0x41, 0x4c, 0x4c, 0x45, 0x4e, 0x47, 0x45, 0x10, 0x06, 0x12, 0x29, 0x0a, 0x25, 0x47, 0x43,
	0x47, 0x5f, 0x47, 0x41, 0x4d, 0x45, 0x5f, 0x42, 0x55, 0x53, 0x49, 0x4e, 0x45, 0x53, 0x53, 0x5f,
	0x54, 0x59, 0x50, 0x45, 0x5f, 0x42, 0x4f, 0x53, 0x53, 0x5f, 0x43, 0x48, 0x41, 0x4c, 0x4c, 0x45,
	0x4e, 0x47, 0x45, 0x10, 0x07, 0x12, 0x29, 0x0a, 0x25, 0x47, 0x43, 0x47, 0x5f, 0x47, 0x41, 0x4d,
	0x45, 0x5f, 0x42, 0x55, 0x53, 0x49, 0x4e, 0x45, 0x53, 0x53, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f,
	0x57, 0x45, 0x45, 0x4b, 0x5f, 0x43, 0x48, 0x41, 0x4c, 0x4c, 0x45, 0x4e, 0x47, 0x45, 0x10, 0x08,
	0x12, 0x2a, 0x0a, 0x26, 0x47, 0x43, 0x47, 0x5f, 0x47, 0x41, 0x4d, 0x45, 0x5f, 0x42, 0x55, 0x53,
	0x49, 0x4e, 0x45, 0x53, 0x53, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x42, 0x52, 0x45, 0x41, 0x4b,
	0x5f, 0x43, 0x48, 0x41, 0x4c, 0x4c, 0x45, 0x4e, 0x47, 0x45, 0x10, 0x09, 0x12, 0x20, 0x0a, 0x1c,
	0x47, 0x43, 0x47, 0x5f, 0x47, 0x41, 0x4d, 0x45, 0x5f, 0x42, 0x55, 0x53, 0x49, 0x4e, 0x45, 0x53,
	0x53, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x51, 0x55, 0x45, 0x53, 0x54, 0x10, 0x0a, 0x12, 0x26,
	0x0a, 0x22, 0x47, 0x43, 0x47, 0x5f, 0x47, 0x41, 0x4d, 0x45, 0x5f, 0x42, 0x55, 0x53, 0x49, 0x4e,
	0x45, 0x53, 0x53, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x47, 0x55, 0x49, 0x44, 0x45, 0x5f, 0x47,
	0x52, 0x4f, 0x55, 0x50, 0x10, 0x0b, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GCGGameBusinessType_proto_rawDescOnce sync.Once
	file_GCGGameBusinessType_proto_rawDescData = file_GCGGameBusinessType_proto_rawDesc
)

func file_GCGGameBusinessType_proto_rawDescGZIP() []byte {
	file_GCGGameBusinessType_proto_rawDescOnce.Do(func() {
		file_GCGGameBusinessType_proto_rawDescData = protoimpl.X.CompressGZIP(file_GCGGameBusinessType_proto_rawDescData)
	})
	return file_GCGGameBusinessType_proto_rawDescData
}

var file_GCGGameBusinessType_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_GCGGameBusinessType_proto_goTypes = []interface{}{
	(GCGGameBusinessType)(0), // 0: GCGGameBusinessType
}
var file_GCGGameBusinessType_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_GCGGameBusinessType_proto_init() }
func file_GCGGameBusinessType_proto_init() {
	if File_GCGGameBusinessType_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_GCGGameBusinessType_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GCGGameBusinessType_proto_goTypes,
		DependencyIndexes: file_GCGGameBusinessType_proto_depIdxs,
		EnumInfos:         file_GCGGameBusinessType_proto_enumTypes,
	}.Build()
	File_GCGGameBusinessType_proto = out.File
	file_GCGGameBusinessType_proto_rawDesc = nil
	file_GCGGameBusinessType_proto_goTypes = nil
	file_GCGGameBusinessType_proto_depIdxs = nil
}
