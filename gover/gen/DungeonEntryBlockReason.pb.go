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
// source: DungeonEntryBlockReason.proto

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

// Obf: DMHCHCJJAKN
type DungeonEntryBlockReason int32

const (
	DungeonEntryBlockReason_DUNGEON_ENTRY_REASON_NONE    DungeonEntryBlockReason = 0
	DungeonEntryBlockReason_DUNGEON_ENTRY_REASON_LEVEL   DungeonEntryBlockReason = 1
	DungeonEntryBlockReason_DUNGEON_ENTRY_REASON_QUEST   DungeonEntryBlockReason = 2
	DungeonEntryBlockReason_DUNGEON_ENTRY_REASON_MULIPLE DungeonEntryBlockReason = 3
)

// Enum value maps for DungeonEntryBlockReason.
var (
	DungeonEntryBlockReason_name = map[int32]string{
		0: "DUNGEON_ENTRY_REASON_NONE",
		1: "DUNGEON_ENTRY_REASON_LEVEL",
		2: "DUNGEON_ENTRY_REASON_QUEST",
		3: "DUNGEON_ENTRY_REASON_MULIPLE",
	}
	DungeonEntryBlockReason_value = map[string]int32{
		"DUNGEON_ENTRY_REASON_NONE":    0,
		"DUNGEON_ENTRY_REASON_LEVEL":   1,
		"DUNGEON_ENTRY_REASON_QUEST":   2,
		"DUNGEON_ENTRY_REASON_MULIPLE": 3,
	}
)

func (x DungeonEntryBlockReason) Enum() *DungeonEntryBlockReason {
	p := new(DungeonEntryBlockReason)
	*p = x
	return p
}

func (x DungeonEntryBlockReason) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (DungeonEntryBlockReason) Descriptor() protoreflect.EnumDescriptor {
	return file_DungeonEntryBlockReason_proto_enumTypes[0].Descriptor()
}

func (DungeonEntryBlockReason) Type() protoreflect.EnumType {
	return &file_DungeonEntryBlockReason_proto_enumTypes[0]
}

func (x DungeonEntryBlockReason) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use DungeonEntryBlockReason.Descriptor instead.
func (DungeonEntryBlockReason) EnumDescriptor() ([]byte, []int) {
	return file_DungeonEntryBlockReason_proto_rawDescGZIP(), []int{0}
}

var File_DungeonEntryBlockReason_proto protoreflect.FileDescriptor

var file_DungeonEntryBlockReason_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x42, 0x6c,
	0x6f, 0x63, 0x6b, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2a,
	0x9a, 0x01, 0x0a, 0x17, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x45, 0x6e, 0x74, 0x72, 0x79,
	0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x12, 0x1d, 0x0a, 0x19, 0x44,
	0x55, 0x4e, 0x47, 0x45, 0x4f, 0x4e, 0x5f, 0x45, 0x4e, 0x54, 0x52, 0x59, 0x5f, 0x52, 0x45, 0x41,
	0x53, 0x4f, 0x4e, 0x5f, 0x4e, 0x4f, 0x4e, 0x45, 0x10, 0x00, 0x12, 0x1e, 0x0a, 0x1a, 0x44, 0x55,
	0x4e, 0x47, 0x45, 0x4f, 0x4e, 0x5f, 0x45, 0x4e, 0x54, 0x52, 0x59, 0x5f, 0x52, 0x45, 0x41, 0x53,
	0x4f, 0x4e, 0x5f, 0x4c, 0x45, 0x56, 0x45, 0x4c, 0x10, 0x01, 0x12, 0x1e, 0x0a, 0x1a, 0x44, 0x55,
	0x4e, 0x47, 0x45, 0x4f, 0x4e, 0x5f, 0x45, 0x4e, 0x54, 0x52, 0x59, 0x5f, 0x52, 0x45, 0x41, 0x53,
	0x4f, 0x4e, 0x5f, 0x51, 0x55, 0x45, 0x53, 0x54, 0x10, 0x02, 0x12, 0x20, 0x0a, 0x1c, 0x44, 0x55,
	0x4e, 0x47, 0x45, 0x4f, 0x4e, 0x5f, 0x45, 0x4e, 0x54, 0x52, 0x59, 0x5f, 0x52, 0x45, 0x41, 0x53,
	0x4f, 0x4e, 0x5f, 0x4d, 0x55, 0x4c, 0x49, 0x50, 0x4c, 0x45, 0x10, 0x03, 0x42, 0x06, 0x5a, 0x04,
	0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_DungeonEntryBlockReason_proto_rawDescOnce sync.Once
	file_DungeonEntryBlockReason_proto_rawDescData = file_DungeonEntryBlockReason_proto_rawDesc
)

func file_DungeonEntryBlockReason_proto_rawDescGZIP() []byte {
	file_DungeonEntryBlockReason_proto_rawDescOnce.Do(func() {
		file_DungeonEntryBlockReason_proto_rawDescData = protoimpl.X.CompressGZIP(file_DungeonEntryBlockReason_proto_rawDescData)
	})
	return file_DungeonEntryBlockReason_proto_rawDescData
}

var file_DungeonEntryBlockReason_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_DungeonEntryBlockReason_proto_goTypes = []interface{}{
	(DungeonEntryBlockReason)(0), // 0: DungeonEntryBlockReason
}
var file_DungeonEntryBlockReason_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_DungeonEntryBlockReason_proto_init() }
func file_DungeonEntryBlockReason_proto_init() {
	if File_DungeonEntryBlockReason_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_DungeonEntryBlockReason_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_DungeonEntryBlockReason_proto_goTypes,
		DependencyIndexes: file_DungeonEntryBlockReason_proto_depIdxs,
		EnumInfos:         file_DungeonEntryBlockReason_proto_enumTypes,
	}.Build()
	File_DungeonEntryBlockReason_proto = out.File
	file_DungeonEntryBlockReason_proto_rawDesc = nil
	file_DungeonEntryBlockReason_proto_goTypes = nil
	file_DungeonEntryBlockReason_proto_depIdxs = nil
}
