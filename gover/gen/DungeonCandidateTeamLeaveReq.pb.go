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
// source: DungeonCandidateTeamLeaveReq.proto

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

// CmdId: 946
// Obf: EPAMAIKAGEP
type DungeonCandidateTeamLeaveReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DungeonCandidateTeamLeaveReq) Reset() {
	*x = DungeonCandidateTeamLeaveReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_DungeonCandidateTeamLeaveReq_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DungeonCandidateTeamLeaveReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DungeonCandidateTeamLeaveReq) ProtoMessage() {}

func (x *DungeonCandidateTeamLeaveReq) ProtoReflect() protoreflect.Message {
	mi := &file_DungeonCandidateTeamLeaveReq_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DungeonCandidateTeamLeaveReq.ProtoReflect.Descriptor instead.
func (*DungeonCandidateTeamLeaveReq) Descriptor() ([]byte, []int) {
	return file_DungeonCandidateTeamLeaveReq_proto_rawDescGZIP(), []int{0}
}

var File_DungeonCandidateTeamLeaveReq_proto protoreflect.FileDescriptor

var file_DungeonCandidateTeamLeaveReq_proto_rawDesc = []byte{
	0x0a, 0x22, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x43, 0x61, 0x6e, 0x64, 0x69, 0x64, 0x61,
	0x74, 0x65, 0x54, 0x65, 0x61, 0x6d, 0x4c, 0x65, 0x61, 0x76, 0x65, 0x52, 0x65, 0x71, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0x1e, 0x0a, 0x1c, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x43,
	0x61, 0x6e, 0x64, 0x69, 0x64, 0x61, 0x74, 0x65, 0x54, 0x65, 0x61, 0x6d, 0x4c, 0x65, 0x61, 0x76,
	0x65, 0x52, 0x65, 0x71, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_DungeonCandidateTeamLeaveReq_proto_rawDescOnce sync.Once
	file_DungeonCandidateTeamLeaveReq_proto_rawDescData = file_DungeonCandidateTeamLeaveReq_proto_rawDesc
)

func file_DungeonCandidateTeamLeaveReq_proto_rawDescGZIP() []byte {
	file_DungeonCandidateTeamLeaveReq_proto_rawDescOnce.Do(func() {
		file_DungeonCandidateTeamLeaveReq_proto_rawDescData = protoimpl.X.CompressGZIP(file_DungeonCandidateTeamLeaveReq_proto_rawDescData)
	})
	return file_DungeonCandidateTeamLeaveReq_proto_rawDescData
}

var file_DungeonCandidateTeamLeaveReq_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_DungeonCandidateTeamLeaveReq_proto_goTypes = []interface{}{
	(*DungeonCandidateTeamLeaveReq)(nil), // 0: DungeonCandidateTeamLeaveReq
}
var file_DungeonCandidateTeamLeaveReq_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_DungeonCandidateTeamLeaveReq_proto_init() }
func file_DungeonCandidateTeamLeaveReq_proto_init() {
	if File_DungeonCandidateTeamLeaveReq_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_DungeonCandidateTeamLeaveReq_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DungeonCandidateTeamLeaveReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_DungeonCandidateTeamLeaveReq_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_DungeonCandidateTeamLeaveReq_proto_goTypes,
		DependencyIndexes: file_DungeonCandidateTeamLeaveReq_proto_depIdxs,
		MessageInfos:      file_DungeonCandidateTeamLeaveReq_proto_msgTypes,
	}.Build()
	File_DungeonCandidateTeamLeaveReq_proto = out.File
	file_DungeonCandidateTeamLeaveReq_proto_rawDesc = nil
	file_DungeonCandidateTeamLeaveReq_proto_goTypes = nil
	file_DungeonCandidateTeamLeaveReq_proto_depIdxs = nil
}
