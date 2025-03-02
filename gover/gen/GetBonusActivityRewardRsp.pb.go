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
// source: GetBonusActivityRewardRsp.proto

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

// CmdId: 2516
// Obf: PGJOMLEKOII
type GetBonusActivityRewardRsp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BonusActivityInfoList *BonusActivityInfo `protobuf:"bytes,4,opt,name=bonus_activity_info_list,json=bonusActivityInfoList,proto3" json:"bonus_activity_info_list,omitempty"`
	Retcode               int32              `protobuf:"varint,9,opt,name=retcode,proto3" json:"retcode,omitempty"`
}

func (x *GetBonusActivityRewardRsp) Reset() {
	*x = GetBonusActivityRewardRsp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GetBonusActivityRewardRsp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetBonusActivityRewardRsp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetBonusActivityRewardRsp) ProtoMessage() {}

func (x *GetBonusActivityRewardRsp) ProtoReflect() protoreflect.Message {
	mi := &file_GetBonusActivityRewardRsp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetBonusActivityRewardRsp.ProtoReflect.Descriptor instead.
func (*GetBonusActivityRewardRsp) Descriptor() ([]byte, []int) {
	return file_GetBonusActivityRewardRsp_proto_rawDescGZIP(), []int{0}
}

func (x *GetBonusActivityRewardRsp) GetBonusActivityInfoList() *BonusActivityInfo {
	if x != nil {
		return x.BonusActivityInfoList
	}
	return nil
}

func (x *GetBonusActivityRewardRsp) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

var File_GetBonusActivityRewardRsp_proto protoreflect.FileDescriptor

var file_GetBonusActivityRewardRsp_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x47, 0x65, 0x74, 0x42, 0x6f, 0x6e, 0x75, 0x73, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69,
	0x74, 0x79, 0x52, 0x65, 0x77, 0x61, 0x72, 0x64, 0x52, 0x73, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x17, 0x42, 0x6f, 0x6e, 0x75, 0x73, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79,
	0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x82, 0x01, 0x0a, 0x19, 0x47,
	0x65, 0x74, 0x42, 0x6f, 0x6e, 0x75, 0x73, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x52,
	0x65, 0x77, 0x61, 0x72, 0x64, 0x52, 0x73, 0x70, 0x12, 0x4b, 0x0a, 0x18, 0x62, 0x6f, 0x6e, 0x75,
	0x73, 0x5f, 0x61, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x5f,
	0x6c, 0x69, 0x73, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x42, 0x6f, 0x6e,
	0x75, 0x73, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x15,
	0x62, 0x6f, 0x6e, 0x75, 0x73, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x49, 0x6e, 0x66,
	0x6f, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65,
	0x18, 0x09, 0x20, 0x01, 0x28, 0x05, 0x52, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x42,
	0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GetBonusActivityRewardRsp_proto_rawDescOnce sync.Once
	file_GetBonusActivityRewardRsp_proto_rawDescData = file_GetBonusActivityRewardRsp_proto_rawDesc
)

func file_GetBonusActivityRewardRsp_proto_rawDescGZIP() []byte {
	file_GetBonusActivityRewardRsp_proto_rawDescOnce.Do(func() {
		file_GetBonusActivityRewardRsp_proto_rawDescData = protoimpl.X.CompressGZIP(file_GetBonusActivityRewardRsp_proto_rawDescData)
	})
	return file_GetBonusActivityRewardRsp_proto_rawDescData
}

var file_GetBonusActivityRewardRsp_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GetBonusActivityRewardRsp_proto_goTypes = []interface{}{
	(*GetBonusActivityRewardRsp)(nil), // 0: GetBonusActivityRewardRsp
	(*BonusActivityInfo)(nil),         // 1: BonusActivityInfo
}
var file_GetBonusActivityRewardRsp_proto_depIdxs = []int32{
	1, // 0: GetBonusActivityRewardRsp.bonus_activity_info_list:type_name -> BonusActivityInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_GetBonusActivityRewardRsp_proto_init() }
func file_GetBonusActivityRewardRsp_proto_init() {
	if File_GetBonusActivityRewardRsp_proto != nil {
		return
	}
	file_BonusActivityInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_GetBonusActivityRewardRsp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetBonusActivityRewardRsp); i {
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
			RawDescriptor: file_GetBonusActivityRewardRsp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GetBonusActivityRewardRsp_proto_goTypes,
		DependencyIndexes: file_GetBonusActivityRewardRsp_proto_depIdxs,
		MessageInfos:      file_GetBonusActivityRewardRsp_proto_msgTypes,
	}.Build()
	File_GetBonusActivityRewardRsp_proto = out.File
	file_GetBonusActivityRewardRsp_proto_rawDesc = nil
	file_GetBonusActivityRewardRsp_proto_goTypes = nil
	file_GetBonusActivityRewardRsp_proto_depIdxs = nil
}
