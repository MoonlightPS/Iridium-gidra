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
// source: ElectroherculesBattleDetailInfo.proto

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

// Obf: HEOBEJGAFJO
type ElectroherculesBattleDetailInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MAABHBPHKED   bool                              `protobuf:"varint,14,opt,name=MAABHBPHKED,proto3" json:"MAABHBPHKED,omitempty"`
	StageInfoList []*ElectroherculesBattleStageInfo `protobuf:"bytes,2,rep,name=stage_info_list,json=stageInfoList,proto3" json:"stage_info_list,omitempty"`
}

func (x *ElectroherculesBattleDetailInfo) Reset() {
	*x = ElectroherculesBattleDetailInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ElectroherculesBattleDetailInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ElectroherculesBattleDetailInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ElectroherculesBattleDetailInfo) ProtoMessage() {}

func (x *ElectroherculesBattleDetailInfo) ProtoReflect() protoreflect.Message {
	mi := &file_ElectroherculesBattleDetailInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ElectroherculesBattleDetailInfo.ProtoReflect.Descriptor instead.
func (*ElectroherculesBattleDetailInfo) Descriptor() ([]byte, []int) {
	return file_ElectroherculesBattleDetailInfo_proto_rawDescGZIP(), []int{0}
}

func (x *ElectroherculesBattleDetailInfo) GetMAABHBPHKED() bool {
	if x != nil {
		return x.MAABHBPHKED
	}
	return false
}

func (x *ElectroherculesBattleDetailInfo) GetStageInfoList() []*ElectroherculesBattleStageInfo {
	if x != nil {
		return x.StageInfoList
	}
	return nil
}

var File_ElectroherculesBattleDetailInfo_proto protoreflect.FileDescriptor

var file_ElectroherculesBattleDetailInfo_proto_rawDesc = []byte{
	0x0a, 0x25, 0x45, 0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f, 0x68, 0x65, 0x72, 0x63, 0x75, 0x6c, 0x65,
	0x73, 0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66,
	0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x24, 0x45, 0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f,
	0x68, 0x65, 0x72, 0x63, 0x75, 0x6c, 0x65, 0x73, 0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x53, 0x74,
	0x61, 0x67, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x8c, 0x01,
	0x0a, 0x1f, 0x45, 0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f, 0x68, 0x65, 0x72, 0x63, 0x75, 0x6c, 0x65,
	0x73, 0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66,
	0x6f, 0x12, 0x20, 0x0a, 0x0b, 0x4d, 0x41, 0x41, 0x42, 0x48, 0x42, 0x50, 0x48, 0x4b, 0x45, 0x44,
	0x18, 0x0e, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x4d, 0x41, 0x41, 0x42, 0x48, 0x42, 0x50, 0x48,
	0x4b, 0x45, 0x44, 0x12, 0x47, 0x0a, 0x0f, 0x73, 0x74, 0x61, 0x67, 0x65, 0x5f, 0x69, 0x6e, 0x66,
	0x6f, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x45,
	0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f, 0x68, 0x65, 0x72, 0x63, 0x75, 0x6c, 0x65, 0x73, 0x42, 0x61,
	0x74, 0x74, 0x6c, 0x65, 0x53, 0x74, 0x61, 0x67, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0d, 0x73,
	0x74, 0x61, 0x67, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x4c, 0x69, 0x73, 0x74, 0x42, 0x06, 0x5a, 0x04,
	0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ElectroherculesBattleDetailInfo_proto_rawDescOnce sync.Once
	file_ElectroherculesBattleDetailInfo_proto_rawDescData = file_ElectroherculesBattleDetailInfo_proto_rawDesc
)

func file_ElectroherculesBattleDetailInfo_proto_rawDescGZIP() []byte {
	file_ElectroherculesBattleDetailInfo_proto_rawDescOnce.Do(func() {
		file_ElectroherculesBattleDetailInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_ElectroherculesBattleDetailInfo_proto_rawDescData)
	})
	return file_ElectroherculesBattleDetailInfo_proto_rawDescData
}

var file_ElectroherculesBattleDetailInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_ElectroherculesBattleDetailInfo_proto_goTypes = []interface{}{
	(*ElectroherculesBattleDetailInfo)(nil), // 0: ElectroherculesBattleDetailInfo
	(*ElectroherculesBattleStageInfo)(nil),  // 1: ElectroherculesBattleStageInfo
}
var file_ElectroherculesBattleDetailInfo_proto_depIdxs = []int32{
	1, // 0: ElectroherculesBattleDetailInfo.stage_info_list:type_name -> ElectroherculesBattleStageInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_ElectroherculesBattleDetailInfo_proto_init() }
func file_ElectroherculesBattleDetailInfo_proto_init() {
	if File_ElectroherculesBattleDetailInfo_proto != nil {
		return
	}
	file_ElectroherculesBattleStageInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_ElectroherculesBattleDetailInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ElectroherculesBattleDetailInfo); i {
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
			RawDescriptor: file_ElectroherculesBattleDetailInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ElectroherculesBattleDetailInfo_proto_goTypes,
		DependencyIndexes: file_ElectroherculesBattleDetailInfo_proto_depIdxs,
		MessageInfos:      file_ElectroherculesBattleDetailInfo_proto_msgTypes,
	}.Build()
	File_ElectroherculesBattleDetailInfo_proto = out.File
	file_ElectroherculesBattleDetailInfo_proto_rawDesc = nil
	file_ElectroherculesBattleDetailInfo_proto_goTypes = nil
	file_ElectroherculesBattleDetailInfo_proto_depIdxs = nil
}
