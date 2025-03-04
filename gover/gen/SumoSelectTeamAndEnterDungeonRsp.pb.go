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
// source: SumoSelectTeamAndEnterDungeonRsp.proto

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

// CmdId: 8398
// Obf: GKFBEOGAOME
type SumoSelectTeamAndEnterDungeonRsp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TeamList     []*SumoTeamData `protobuf:"bytes,13,rep,name=team_list,json=teamList,proto3" json:"team_list,omitempty"`
	ActivityId   uint32          `protobuf:"varint,9,opt,name=activity_id,json=activityId,proto3" json:"activity_id,omitempty"`
	DifficultyId uint32          `protobuf:"varint,6,opt,name=difficulty_id,json=difficultyId,proto3" json:"difficulty_id,omitempty"`
	Retcode      int32           `protobuf:"varint,5,opt,name=retcode,proto3" json:"retcode,omitempty"`
	StageId      uint32          `protobuf:"varint,7,opt,name=stage_id,json=stageId,proto3" json:"stage_id,omitempty"`
}

func (x *SumoSelectTeamAndEnterDungeonRsp) Reset() {
	*x = SumoSelectTeamAndEnterDungeonRsp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_SumoSelectTeamAndEnterDungeonRsp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SumoSelectTeamAndEnterDungeonRsp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SumoSelectTeamAndEnterDungeonRsp) ProtoMessage() {}

func (x *SumoSelectTeamAndEnterDungeonRsp) ProtoReflect() protoreflect.Message {
	mi := &file_SumoSelectTeamAndEnterDungeonRsp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SumoSelectTeamAndEnterDungeonRsp.ProtoReflect.Descriptor instead.
func (*SumoSelectTeamAndEnterDungeonRsp) Descriptor() ([]byte, []int) {
	return file_SumoSelectTeamAndEnterDungeonRsp_proto_rawDescGZIP(), []int{0}
}

func (x *SumoSelectTeamAndEnterDungeonRsp) GetTeamList() []*SumoTeamData {
	if x != nil {
		return x.TeamList
	}
	return nil
}

func (x *SumoSelectTeamAndEnterDungeonRsp) GetActivityId() uint32 {
	if x != nil {
		return x.ActivityId
	}
	return 0
}

func (x *SumoSelectTeamAndEnterDungeonRsp) GetDifficultyId() uint32 {
	if x != nil {
		return x.DifficultyId
	}
	return 0
}

func (x *SumoSelectTeamAndEnterDungeonRsp) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

func (x *SumoSelectTeamAndEnterDungeonRsp) GetStageId() uint32 {
	if x != nil {
		return x.StageId
	}
	return 0
}

var File_SumoSelectTeamAndEnterDungeonRsp_proto protoreflect.FileDescriptor

var file_SumoSelectTeamAndEnterDungeonRsp_proto_rawDesc = []byte{
	0x0a, 0x26, 0x53, 0x75, 0x6d, 0x6f, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x54, 0x65, 0x61, 0x6d,
	0x41, 0x6e, 0x64, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x52,
	0x73, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x53, 0x75, 0x6d, 0x6f, 0x54, 0x65,
	0x61, 0x6d, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc9, 0x01, 0x0a,
	0x20, 0x53, 0x75, 0x6d, 0x6f, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x54, 0x65, 0x61, 0x6d, 0x41,
	0x6e, 0x64, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x52, 0x73,
	0x70, 0x12, 0x2a, 0x0a, 0x09, 0x74, 0x65, 0x61, 0x6d, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0d,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x53, 0x75, 0x6d, 0x6f, 0x54, 0x65, 0x61, 0x6d, 0x44,
	0x61, 0x74, 0x61, 0x52, 0x08, 0x74, 0x65, 0x61, 0x6d, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x1f, 0x0a,
	0x0b, 0x61, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x09, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x0a, 0x61, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x49, 0x64, 0x12, 0x23,
	0x0a, 0x0d, 0x64, 0x69, 0x66, 0x66, 0x69, 0x63, 0x75, 0x6c, 0x74, 0x79, 0x5f, 0x69, 0x64, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0c, 0x64, 0x69, 0x66, 0x66, 0x69, 0x63, 0x75, 0x6c, 0x74,
	0x79, 0x49, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x05, 0x52, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x19, 0x0a,
	0x08, 0x73, 0x74, 0x61, 0x67, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x07, 0x73, 0x74, 0x61, 0x67, 0x65, 0x49, 0x64, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_SumoSelectTeamAndEnterDungeonRsp_proto_rawDescOnce sync.Once
	file_SumoSelectTeamAndEnterDungeonRsp_proto_rawDescData = file_SumoSelectTeamAndEnterDungeonRsp_proto_rawDesc
)

func file_SumoSelectTeamAndEnterDungeonRsp_proto_rawDescGZIP() []byte {
	file_SumoSelectTeamAndEnterDungeonRsp_proto_rawDescOnce.Do(func() {
		file_SumoSelectTeamAndEnterDungeonRsp_proto_rawDescData = protoimpl.X.CompressGZIP(file_SumoSelectTeamAndEnterDungeonRsp_proto_rawDescData)
	})
	return file_SumoSelectTeamAndEnterDungeonRsp_proto_rawDescData
}

var file_SumoSelectTeamAndEnterDungeonRsp_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_SumoSelectTeamAndEnterDungeonRsp_proto_goTypes = []interface{}{
	(*SumoSelectTeamAndEnterDungeonRsp)(nil), // 0: SumoSelectTeamAndEnterDungeonRsp
	(*SumoTeamData)(nil),                     // 1: SumoTeamData
}
var file_SumoSelectTeamAndEnterDungeonRsp_proto_depIdxs = []int32{
	1, // 0: SumoSelectTeamAndEnterDungeonRsp.team_list:type_name -> SumoTeamData
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_SumoSelectTeamAndEnterDungeonRsp_proto_init() }
func file_SumoSelectTeamAndEnterDungeonRsp_proto_init() {
	if File_SumoSelectTeamAndEnterDungeonRsp_proto != nil {
		return
	}
	file_SumoTeamData_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_SumoSelectTeamAndEnterDungeonRsp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SumoSelectTeamAndEnterDungeonRsp); i {
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
			RawDescriptor: file_SumoSelectTeamAndEnterDungeonRsp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_SumoSelectTeamAndEnterDungeonRsp_proto_goTypes,
		DependencyIndexes: file_SumoSelectTeamAndEnterDungeonRsp_proto_depIdxs,
		MessageInfos:      file_SumoSelectTeamAndEnterDungeonRsp_proto_msgTypes,
	}.Build()
	File_SumoSelectTeamAndEnterDungeonRsp_proto = out.File
	file_SumoSelectTeamAndEnterDungeonRsp_proto_rawDesc = nil
	file_SumoSelectTeamAndEnterDungeonRsp_proto_goTypes = nil
	file_SumoSelectTeamAndEnterDungeonRsp_proto_depIdxs = nil
}
