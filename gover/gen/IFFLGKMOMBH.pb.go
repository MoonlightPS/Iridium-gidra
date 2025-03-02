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
// source: IFFLGKMOMBH.proto

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

type IFFLGKMOMBH int32

const (
	IFFLGKMOMBH_IFFLGKMOMBH_ReportReasonSubtypeNone               IFFLGKMOMBH = 0
	IFFLGKMOMBH_IFFLGKMOMBH_ReportReasonSubtypeInvalidNickname    IFFLGKMOMBH = 1
	IFFLGKMOMBH_IFFLGKMOMBH_ReportReasonSubtypeInvalidSignature   IFFLGKMOMBH = 2
	IFFLGKMOMBH_IFFLGKMOMBH_ReportReasonSubtypeInvalidArrangement IFFLGKMOMBH = 3
	IFFLGKMOMBH_IFFLGKMOMBH_ReportReasonSubtypeInvalidChat        IFFLGKMOMBH = 4
	IFFLGKMOMBH_IFFLGKMOMBH_ReportReasonSubtypeInvalidAvatarName  IFFLGKMOMBH = 5
	IFFLGKMOMBH_IFFLGKMOMBH_ReportReasonSubtypeInvalidOther       IFFLGKMOMBH = 6
)

// Enum value maps for IFFLGKMOMBH.
var (
	IFFLGKMOMBH_name = map[int32]string{
		0: "IFFLGKMOMBH_ReportReasonSubtypeNone",
		1: "IFFLGKMOMBH_ReportReasonSubtypeInvalidNickname",
		2: "IFFLGKMOMBH_ReportReasonSubtypeInvalidSignature",
		3: "IFFLGKMOMBH_ReportReasonSubtypeInvalidArrangement",
		4: "IFFLGKMOMBH_ReportReasonSubtypeInvalidChat",
		5: "IFFLGKMOMBH_ReportReasonSubtypeInvalidAvatarName",
		6: "IFFLGKMOMBH_ReportReasonSubtypeInvalidOther",
	}
	IFFLGKMOMBH_value = map[string]int32{
		"IFFLGKMOMBH_ReportReasonSubtypeNone":               0,
		"IFFLGKMOMBH_ReportReasonSubtypeInvalidNickname":    1,
		"IFFLGKMOMBH_ReportReasonSubtypeInvalidSignature":   2,
		"IFFLGKMOMBH_ReportReasonSubtypeInvalidArrangement": 3,
		"IFFLGKMOMBH_ReportReasonSubtypeInvalidChat":        4,
		"IFFLGKMOMBH_ReportReasonSubtypeInvalidAvatarName":  5,
		"IFFLGKMOMBH_ReportReasonSubtypeInvalidOther":       6,
	}
)

func (x IFFLGKMOMBH) Enum() *IFFLGKMOMBH {
	p := new(IFFLGKMOMBH)
	*p = x
	return p
}

func (x IFFLGKMOMBH) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (IFFLGKMOMBH) Descriptor() protoreflect.EnumDescriptor {
	return file_IFFLGKMOMBH_proto_enumTypes[0].Descriptor()
}

func (IFFLGKMOMBH) Type() protoreflect.EnumType {
	return &file_IFFLGKMOMBH_proto_enumTypes[0]
}

func (x IFFLGKMOMBH) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use IFFLGKMOMBH.Descriptor instead.
func (IFFLGKMOMBH) EnumDescriptor() ([]byte, []int) {
	return file_IFFLGKMOMBH_proto_rawDescGZIP(), []int{0}
}

var File_IFFLGKMOMBH_proto protoreflect.FileDescriptor

var file_IFFLGKMOMBH_proto_rawDesc = []byte{
	0x0a, 0x11, 0x49, 0x46, 0x46, 0x4c, 0x47, 0x4b, 0x4d, 0x4f, 0x4d, 0x42, 0x48, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2a, 0xed, 0x02, 0x0a, 0x0b, 0x49, 0x46, 0x46, 0x4c, 0x47, 0x4b, 0x4d, 0x4f,
	0x4d, 0x42, 0x48, 0x12, 0x27, 0x0a, 0x23, 0x49, 0x46, 0x46, 0x4c, 0x47, 0x4b, 0x4d, 0x4f, 0x4d,
	0x42, 0x48, 0x5f, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x53,
	0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x4e, 0x6f, 0x6e, 0x65, 0x10, 0x00, 0x12, 0x32, 0x0a, 0x2e,
	0x49, 0x46, 0x46, 0x4c, 0x47, 0x4b, 0x4d, 0x4f, 0x4d, 0x42, 0x48, 0x5f, 0x52, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x49,
	0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x4e, 0x69, 0x63, 0x6b, 0x6e, 0x61, 0x6d, 0x65, 0x10, 0x01,
	0x12, 0x33, 0x0a, 0x2f, 0x49, 0x46, 0x46, 0x4c, 0x47, 0x4b, 0x4d, 0x4f, 0x4d, 0x42, 0x48, 0x5f,
	0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x53, 0x75, 0x62, 0x74,
	0x79, 0x70, 0x65, 0x49, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74,
	0x75, 0x72, 0x65, 0x10, 0x02, 0x12, 0x35, 0x0a, 0x31, 0x49, 0x46, 0x46, 0x4c, 0x47, 0x4b, 0x4d,
	0x4f, 0x4d, 0x42, 0x48, 0x5f, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x52, 0x65, 0x61, 0x73, 0x6f,
	0x6e, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x49, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x41,
	0x72, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x10, 0x03, 0x12, 0x2e, 0x0a, 0x2a,
	0x49, 0x46, 0x46, 0x4c, 0x47, 0x4b, 0x4d, 0x4f, 0x4d, 0x42, 0x48, 0x5f, 0x52, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x49,
	0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x43, 0x68, 0x61, 0x74, 0x10, 0x04, 0x12, 0x34, 0x0a, 0x30,
	0x49, 0x46, 0x46, 0x4c, 0x47, 0x4b, 0x4d, 0x4f, 0x4d, 0x42, 0x48, 0x5f, 0x52, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x49,
	0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x41, 0x76, 0x61, 0x74, 0x61, 0x72, 0x4e, 0x61, 0x6d, 0x65,
	0x10, 0x05, 0x12, 0x2f, 0x0a, 0x2b, 0x49, 0x46, 0x46, 0x4c, 0x47, 0x4b, 0x4d, 0x4f, 0x4d, 0x42,
	0x48, 0x5f, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x53, 0x75,
	0x62, 0x74, 0x79, 0x70, 0x65, 0x49, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x4f, 0x74, 0x68, 0x65,
	0x72, 0x10, 0x06, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_IFFLGKMOMBH_proto_rawDescOnce sync.Once
	file_IFFLGKMOMBH_proto_rawDescData = file_IFFLGKMOMBH_proto_rawDesc
)

func file_IFFLGKMOMBH_proto_rawDescGZIP() []byte {
	file_IFFLGKMOMBH_proto_rawDescOnce.Do(func() {
		file_IFFLGKMOMBH_proto_rawDescData = protoimpl.X.CompressGZIP(file_IFFLGKMOMBH_proto_rawDescData)
	})
	return file_IFFLGKMOMBH_proto_rawDescData
}

var file_IFFLGKMOMBH_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_IFFLGKMOMBH_proto_goTypes = []interface{}{
	(IFFLGKMOMBH)(0), // 0: IFFLGKMOMBH
}
var file_IFFLGKMOMBH_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_IFFLGKMOMBH_proto_init() }
func file_IFFLGKMOMBH_proto_init() {
	if File_IFFLGKMOMBH_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_IFFLGKMOMBH_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_IFFLGKMOMBH_proto_goTypes,
		DependencyIndexes: file_IFFLGKMOMBH_proto_depIdxs,
		EnumInfos:         file_IFFLGKMOMBH_proto_enumTypes,
	}.Build()
	File_IFFLGKMOMBH_proto = out.File
	file_IFFLGKMOMBH_proto_rawDesc = nil
	file_IFFLGKMOMBH_proto_goTypes = nil
	file_IFFLGKMOMBH_proto_depIdxs = nil
}
