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
// source: ElectroherculesBattleStageInfo.proto

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

// Obf: EBCDNHPAAKJ
type ElectroherculesBattleStageInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IsStageOpen   bool                              `protobuf:"varint,8,opt,name=is_stage_open,json=isStageOpen,proto3" json:"is_stage_open,omitempty"`
	LevelInfoList []*ElectroherculesBattleLevelInfo `protobuf:"bytes,6,rep,name=level_info_list,json=levelInfoList,proto3" json:"level_info_list,omitempty"`
	StageId       uint32                            `protobuf:"varint,4,opt,name=stage_id,json=stageId,proto3" json:"stage_id,omitempty"`
}

func (x *ElectroherculesBattleStageInfo) Reset() {
	*x = ElectroherculesBattleStageInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ElectroherculesBattleStageInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ElectroherculesBattleStageInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ElectroherculesBattleStageInfo) ProtoMessage() {}

func (x *ElectroherculesBattleStageInfo) ProtoReflect() protoreflect.Message {
	mi := &file_ElectroherculesBattleStageInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ElectroherculesBattleStageInfo.ProtoReflect.Descriptor instead.
func (*ElectroherculesBattleStageInfo) Descriptor() ([]byte, []int) {
	return file_ElectroherculesBattleStageInfo_proto_rawDescGZIP(), []int{0}
}

func (x *ElectroherculesBattleStageInfo) GetIsStageOpen() bool {
	if x != nil {
		return x.IsStageOpen
	}
	return false
}

func (x *ElectroherculesBattleStageInfo) GetLevelInfoList() []*ElectroherculesBattleLevelInfo {
	if x != nil {
		return x.LevelInfoList
	}
	return nil
}

func (x *ElectroherculesBattleStageInfo) GetStageId() uint32 {
	if x != nil {
		return x.StageId
	}
	return 0
}

var File_ElectroherculesBattleStageInfo_proto protoreflect.FileDescriptor

var file_ElectroherculesBattleStageInfo_proto_rawDesc = []byte{
	0x0a, 0x24, 0x45, 0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f, 0x68, 0x65, 0x72, 0x63, 0x75, 0x6c, 0x65,
	0x73, 0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x53, 0x74, 0x61, 0x67, 0x65, 0x49, 0x6e, 0x66, 0x6f,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x24, 0x45, 0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f, 0x68,
	0x65, 0x72, 0x63, 0x75, 0x6c, 0x65, 0x73, 0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x4c, 0x65, 0x76,
	0x65, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa8, 0x01, 0x0a,
	0x1e, 0x45, 0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f, 0x68, 0x65, 0x72, 0x63, 0x75, 0x6c, 0x65, 0x73,
	0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x53, 0x74, 0x61, 0x67, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x12,
	0x22, 0x0a, 0x0d, 0x69, 0x73, 0x5f, 0x73, 0x74, 0x61, 0x67, 0x65, 0x5f, 0x6f, 0x70, 0x65, 0x6e,
	0x18, 0x08, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x69, 0x73, 0x53, 0x74, 0x61, 0x67, 0x65, 0x4f,
	0x70, 0x65, 0x6e, 0x12, 0x47, 0x0a, 0x0f, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x5f, 0x69, 0x6e, 0x66,
	0x6f, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x45,
	0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f, 0x68, 0x65, 0x72, 0x63, 0x75, 0x6c, 0x65, 0x73, 0x42, 0x61,
	0x74, 0x74, 0x6c, 0x65, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0d, 0x6c,
	0x65, 0x76, 0x65, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x19, 0x0a, 0x08,
	0x73, 0x74, 0x61, 0x67, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07,
	0x73, 0x74, 0x61, 0x67, 0x65, 0x49, 0x64, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ElectroherculesBattleStageInfo_proto_rawDescOnce sync.Once
	file_ElectroherculesBattleStageInfo_proto_rawDescData = file_ElectroherculesBattleStageInfo_proto_rawDesc
)

func file_ElectroherculesBattleStageInfo_proto_rawDescGZIP() []byte {
	file_ElectroherculesBattleStageInfo_proto_rawDescOnce.Do(func() {
		file_ElectroherculesBattleStageInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_ElectroherculesBattleStageInfo_proto_rawDescData)
	})
	return file_ElectroherculesBattleStageInfo_proto_rawDescData
}

var file_ElectroherculesBattleStageInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_ElectroherculesBattleStageInfo_proto_goTypes = []interface{}{
	(*ElectroherculesBattleStageInfo)(nil), // 0: ElectroherculesBattleStageInfo
	(*ElectroherculesBattleLevelInfo)(nil), // 1: ElectroherculesBattleLevelInfo
}
var file_ElectroherculesBattleStageInfo_proto_depIdxs = []int32{
	1, // 0: ElectroherculesBattleStageInfo.level_info_list:type_name -> ElectroherculesBattleLevelInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_ElectroherculesBattleStageInfo_proto_init() }
func file_ElectroherculesBattleStageInfo_proto_init() {
	if File_ElectroherculesBattleStageInfo_proto != nil {
		return
	}
	file_ElectroherculesBattleLevelInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_ElectroherculesBattleStageInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ElectroherculesBattleStageInfo); i {
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
			RawDescriptor: file_ElectroherculesBattleStageInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ElectroherculesBattleStageInfo_proto_goTypes,
		DependencyIndexes: file_ElectroherculesBattleStageInfo_proto_depIdxs,
		MessageInfos:      file_ElectroherculesBattleStageInfo_proto_msgTypes,
	}.Build()
	File_ElectroherculesBattleStageInfo_proto = out.File
	file_ElectroherculesBattleStageInfo_proto_rawDesc = nil
	file_ElectroherculesBattleStageInfo_proto_goTypes = nil
	file_ElectroherculesBattleStageInfo_proto_depIdxs = nil
}
