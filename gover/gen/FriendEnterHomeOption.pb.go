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
// source: FriendEnterHomeOption.proto

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

// Obf: CEAPGMBAHFJ
type FriendEnterHomeOption int32

const (
	FriendEnterHomeOption_FRIEND_ENTER_HOME_OPTION_NEED_CONFIRM FriendEnterHomeOption = 0
	FriendEnterHomeOption_FRIEND_ENTER_HOME_OPTION_REFUSE       FriendEnterHomeOption = 1
	FriendEnterHomeOption_FRIEND_ENTER_HOME_OPTION_DIRECT       FriendEnterHomeOption = 2
)

// Enum value maps for FriendEnterHomeOption.
var (
	FriendEnterHomeOption_name = map[int32]string{
		0: "FRIEND_ENTER_HOME_OPTION_NEED_CONFIRM",
		1: "FRIEND_ENTER_HOME_OPTION_REFUSE",
		2: "FRIEND_ENTER_HOME_OPTION_DIRECT",
	}
	FriendEnterHomeOption_value = map[string]int32{
		"FRIEND_ENTER_HOME_OPTION_NEED_CONFIRM": 0,
		"FRIEND_ENTER_HOME_OPTION_REFUSE":       1,
		"FRIEND_ENTER_HOME_OPTION_DIRECT":       2,
	}
)

func (x FriendEnterHomeOption) Enum() *FriendEnterHomeOption {
	p := new(FriendEnterHomeOption)
	*p = x
	return p
}

func (x FriendEnterHomeOption) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (FriendEnterHomeOption) Descriptor() protoreflect.EnumDescriptor {
	return file_FriendEnterHomeOption_proto_enumTypes[0].Descriptor()
}

func (FriendEnterHomeOption) Type() protoreflect.EnumType {
	return &file_FriendEnterHomeOption_proto_enumTypes[0]
}

func (x FriendEnterHomeOption) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use FriendEnterHomeOption.Descriptor instead.
func (FriendEnterHomeOption) EnumDescriptor() ([]byte, []int) {
	return file_FriendEnterHomeOption_proto_rawDescGZIP(), []int{0}
}

var File_FriendEnterHomeOption_proto protoreflect.FileDescriptor

var file_FriendEnterHomeOption_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x46, 0x72, 0x69, 0x65, 0x6e, 0x64, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x48, 0x6f, 0x6d,
	0x65, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2a, 0x8c, 0x01,
	0x0a, 0x15, 0x46, 0x72, 0x69, 0x65, 0x6e, 0x64, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x48, 0x6f, 0x6d,
	0x65, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x29, 0x0a, 0x25, 0x46, 0x52, 0x49, 0x45, 0x4e,
	0x44, 0x5f, 0x45, 0x4e, 0x54, 0x45, 0x52, 0x5f, 0x48, 0x4f, 0x4d, 0x45, 0x5f, 0x4f, 0x50, 0x54,
	0x49, 0x4f, 0x4e, 0x5f, 0x4e, 0x45, 0x45, 0x44, 0x5f, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x52, 0x4d,
	0x10, 0x00, 0x12, 0x23, 0x0a, 0x1f, 0x46, 0x52, 0x49, 0x45, 0x4e, 0x44, 0x5f, 0x45, 0x4e, 0x54,
	0x45, 0x52, 0x5f, 0x48, 0x4f, 0x4d, 0x45, 0x5f, 0x4f, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x52,
	0x45, 0x46, 0x55, 0x53, 0x45, 0x10, 0x01, 0x12, 0x23, 0x0a, 0x1f, 0x46, 0x52, 0x49, 0x45, 0x4e,
	0x44, 0x5f, 0x45, 0x4e, 0x54, 0x45, 0x52, 0x5f, 0x48, 0x4f, 0x4d, 0x45, 0x5f, 0x4f, 0x50, 0x54,
	0x49, 0x4f, 0x4e, 0x5f, 0x44, 0x49, 0x52, 0x45, 0x43, 0x54, 0x10, 0x02, 0x42, 0x06, 0x5a, 0x04,
	0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_FriendEnterHomeOption_proto_rawDescOnce sync.Once
	file_FriendEnterHomeOption_proto_rawDescData = file_FriendEnterHomeOption_proto_rawDesc
)

func file_FriendEnterHomeOption_proto_rawDescGZIP() []byte {
	file_FriendEnterHomeOption_proto_rawDescOnce.Do(func() {
		file_FriendEnterHomeOption_proto_rawDescData = protoimpl.X.CompressGZIP(file_FriendEnterHomeOption_proto_rawDescData)
	})
	return file_FriendEnterHomeOption_proto_rawDescData
}

var file_FriendEnterHomeOption_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_FriendEnterHomeOption_proto_goTypes = []interface{}{
	(FriendEnterHomeOption)(0), // 0: FriendEnterHomeOption
}
var file_FriendEnterHomeOption_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_FriendEnterHomeOption_proto_init() }
func file_FriendEnterHomeOption_proto_init() {
	if File_FriendEnterHomeOption_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_FriendEnterHomeOption_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_FriendEnterHomeOption_proto_goTypes,
		DependencyIndexes: file_FriendEnterHomeOption_proto_depIdxs,
		EnumInfos:         file_FriendEnterHomeOption_proto_enumTypes,
	}.Build()
	File_FriendEnterHomeOption_proto = out.File
	file_FriendEnterHomeOption_proto_rawDesc = nil
	file_FriendEnterHomeOption_proto_goTypes = nil
	file_FriendEnterHomeOption_proto_depIdxs = nil
}
