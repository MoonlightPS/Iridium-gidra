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
// source: GMIOAJDAFAB.proto

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

type GMIOAJDAFAB int32

const (
	GMIOAJDAFAB_GMIOAJDAFAB_EnterUgcDungeonNone               GMIOAJDAFAB = 0
	GMIOAJDAFAB_GMIOAJDAFAB_EnterUgcDungeonTrialInEditDungeon GMIOAJDAFAB = 1
	GMIOAJDAFAB_GMIOAJDAFAB_EnterUgcDungeonTrialInWorld       GMIOAJDAFAB = 2
	GMIOAJDAFAB_GMIOAJDAFAB_EnterUgcDungeonPlay               GMIOAJDAFAB = 3
	GMIOAJDAFAB_GMIOAJDAFAB_EnterUgcDungeonOfficial           GMIOAJDAFAB = 4
	GMIOAJDAFAB_GMIOAJDAFAB_EnterUgcDungeonByGm               GMIOAJDAFAB = 5
	GMIOAJDAFAB_GMIOAJDAFAB_EnterUgcDungeonByEdit             GMIOAJDAFAB = 6
	GMIOAJDAFAB_GMIOAJDAFAB_EnterUgcDungeonTrialOneRoom       GMIOAJDAFAB = 7
)

// Enum value maps for GMIOAJDAFAB.
var (
	GMIOAJDAFAB_name = map[int32]string{
		0: "GMIOAJDAFAB_EnterUgcDungeonNone",
		1: "GMIOAJDAFAB_EnterUgcDungeonTrialInEditDungeon",
		2: "GMIOAJDAFAB_EnterUgcDungeonTrialInWorld",
		3: "GMIOAJDAFAB_EnterUgcDungeonPlay",
		4: "GMIOAJDAFAB_EnterUgcDungeonOfficial",
		5: "GMIOAJDAFAB_EnterUgcDungeonByGm",
		6: "GMIOAJDAFAB_EnterUgcDungeonByEdit",
		7: "GMIOAJDAFAB_EnterUgcDungeonTrialOneRoom",
	}
	GMIOAJDAFAB_value = map[string]int32{
		"GMIOAJDAFAB_EnterUgcDungeonNone":               0,
		"GMIOAJDAFAB_EnterUgcDungeonTrialInEditDungeon": 1,
		"GMIOAJDAFAB_EnterUgcDungeonTrialInWorld":       2,
		"GMIOAJDAFAB_EnterUgcDungeonPlay":               3,
		"GMIOAJDAFAB_EnterUgcDungeonOfficial":           4,
		"GMIOAJDAFAB_EnterUgcDungeonByGm":               5,
		"GMIOAJDAFAB_EnterUgcDungeonByEdit":             6,
		"GMIOAJDAFAB_EnterUgcDungeonTrialOneRoom":       7,
	}
)

func (x GMIOAJDAFAB) Enum() *GMIOAJDAFAB {
	p := new(GMIOAJDAFAB)
	*p = x
	return p
}

func (x GMIOAJDAFAB) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (GMIOAJDAFAB) Descriptor() protoreflect.EnumDescriptor {
	return file_GMIOAJDAFAB_proto_enumTypes[0].Descriptor()
}

func (GMIOAJDAFAB) Type() protoreflect.EnumType {
	return &file_GMIOAJDAFAB_proto_enumTypes[0]
}

func (x GMIOAJDAFAB) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use GMIOAJDAFAB.Descriptor instead.
func (GMIOAJDAFAB) EnumDescriptor() ([]byte, []int) {
	return file_GMIOAJDAFAB_proto_rawDescGZIP(), []int{0}
}

var File_GMIOAJDAFAB_proto protoreflect.FileDescriptor

var file_GMIOAJDAFAB_proto_rawDesc = []byte{
	0x0a, 0x11, 0x47, 0x4d, 0x49, 0x4f, 0x41, 0x4a, 0x44, 0x41, 0x46, 0x41, 0x42, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2a, 0xd9, 0x02, 0x0a, 0x0b, 0x47, 0x4d, 0x49, 0x4f, 0x41, 0x4a, 0x44, 0x41,
	0x46, 0x41, 0x42, 0x12, 0x23, 0x0a, 0x1f, 0x47, 0x4d, 0x49, 0x4f, 0x41, 0x4a, 0x44, 0x41, 0x46,
	0x41, 0x42, 0x5f, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x55, 0x67, 0x63, 0x44, 0x75, 0x6e, 0x67, 0x65,
	0x6f, 0x6e, 0x4e, 0x6f, 0x6e, 0x65, 0x10, 0x00, 0x12, 0x31, 0x0a, 0x2d, 0x47, 0x4d, 0x49, 0x4f,
	0x41, 0x4a, 0x44, 0x41, 0x46, 0x41, 0x42, 0x5f, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x55, 0x67, 0x63,
	0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x54, 0x72, 0x69, 0x61, 0x6c, 0x49, 0x6e, 0x45, 0x64,
	0x69, 0x74, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x10, 0x01, 0x12, 0x2b, 0x0a, 0x27, 0x47,
	0x4d, 0x49, 0x4f, 0x41, 0x4a, 0x44, 0x41, 0x46, 0x41, 0x42, 0x5f, 0x45, 0x6e, 0x74, 0x65, 0x72,
	0x55, 0x67, 0x63, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x54, 0x72, 0x69, 0x61, 0x6c, 0x49,
	0x6e, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x10, 0x02, 0x12, 0x23, 0x0a, 0x1f, 0x47, 0x4d, 0x49, 0x4f,
	0x41, 0x4a, 0x44, 0x41, 0x46, 0x41, 0x42, 0x5f, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x55, 0x67, 0x63,
	0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x50, 0x6c, 0x61, 0x79, 0x10, 0x03, 0x12, 0x27, 0x0a,
	0x23, 0x47, 0x4d, 0x49, 0x4f, 0x41, 0x4a, 0x44, 0x41, 0x46, 0x41, 0x42, 0x5f, 0x45, 0x6e, 0x74,
	0x65, 0x72, 0x55, 0x67, 0x63, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x4f, 0x66, 0x66, 0x69,
	0x63, 0x69, 0x61, 0x6c, 0x10, 0x04, 0x12, 0x23, 0x0a, 0x1f, 0x47, 0x4d, 0x49, 0x4f, 0x41, 0x4a,
	0x44, 0x41, 0x46, 0x41, 0x42, 0x5f, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x55, 0x67, 0x63, 0x44, 0x75,
	0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x42, 0x79, 0x47, 0x6d, 0x10, 0x05, 0x12, 0x25, 0x0a, 0x21, 0x47,
	0x4d, 0x49, 0x4f, 0x41, 0x4a, 0x44, 0x41, 0x46, 0x41, 0x42, 0x5f, 0x45, 0x6e, 0x74, 0x65, 0x72,
	0x55, 0x67, 0x63, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x42, 0x79, 0x45, 0x64, 0x69, 0x74,
	0x10, 0x06, 0x12, 0x2b, 0x0a, 0x27, 0x47, 0x4d, 0x49, 0x4f, 0x41, 0x4a, 0x44, 0x41, 0x46, 0x41,
	0x42, 0x5f, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x55, 0x67, 0x63, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f,
	0x6e, 0x54, 0x72, 0x69, 0x61, 0x6c, 0x4f, 0x6e, 0x65, 0x52, 0x6f, 0x6f, 0x6d, 0x10, 0x07, 0x42,
	0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GMIOAJDAFAB_proto_rawDescOnce sync.Once
	file_GMIOAJDAFAB_proto_rawDescData = file_GMIOAJDAFAB_proto_rawDesc
)

func file_GMIOAJDAFAB_proto_rawDescGZIP() []byte {
	file_GMIOAJDAFAB_proto_rawDescOnce.Do(func() {
		file_GMIOAJDAFAB_proto_rawDescData = protoimpl.X.CompressGZIP(file_GMIOAJDAFAB_proto_rawDescData)
	})
	return file_GMIOAJDAFAB_proto_rawDescData
}

var file_GMIOAJDAFAB_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_GMIOAJDAFAB_proto_goTypes = []interface{}{
	(GMIOAJDAFAB)(0), // 0: GMIOAJDAFAB
}
var file_GMIOAJDAFAB_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_GMIOAJDAFAB_proto_init() }
func file_GMIOAJDAFAB_proto_init() {
	if File_GMIOAJDAFAB_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_GMIOAJDAFAB_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GMIOAJDAFAB_proto_goTypes,
		DependencyIndexes: file_GMIOAJDAFAB_proto_depIdxs,
		EnumInfos:         file_GMIOAJDAFAB_proto_enumTypes,
	}.Build()
	File_GMIOAJDAFAB_proto = out.File
	file_GMIOAJDAFAB_proto_rawDesc = nil
	file_GMIOAJDAFAB_proto_goTypes = nil
	file_GMIOAJDAFAB_proto_depIdxs = nil
}
