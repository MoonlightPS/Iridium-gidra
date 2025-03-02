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
// source: AsterLittleDetailInfo.proto

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

// Obf: LGDFNBJMBAB
type AsterLittleDetailInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	StageId        uint32                `protobuf:"varint,9,opt,name=stage_id,json=stageId,proto3" json:"stage_id,omitempty"`
	StageState     AsterLittleStageState `protobuf:"varint,7,opt,name=stage_state,json=stageState,proto3,enum=AsterLittleStageState" json:"stage_state,omitempty"`
	StageBeginTime uint32                `protobuf:"varint,14,opt,name=stage_begin_time,json=stageBeginTime,proto3" json:"stage_begin_time,omitempty"`
	BeginTime      uint32                `protobuf:"varint,4,opt,name=begin_time,json=beginTime,proto3" json:"begin_time,omitempty"`
	IsOpen         bool                  `protobuf:"varint,5,opt,name=is_open,json=isOpen,proto3" json:"is_open,omitempty"`
}

func (x *AsterLittleDetailInfo) Reset() {
	*x = AsterLittleDetailInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_AsterLittleDetailInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AsterLittleDetailInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AsterLittleDetailInfo) ProtoMessage() {}

func (x *AsterLittleDetailInfo) ProtoReflect() protoreflect.Message {
	mi := &file_AsterLittleDetailInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AsterLittleDetailInfo.ProtoReflect.Descriptor instead.
func (*AsterLittleDetailInfo) Descriptor() ([]byte, []int) {
	return file_AsterLittleDetailInfo_proto_rawDescGZIP(), []int{0}
}

func (x *AsterLittleDetailInfo) GetStageId() uint32 {
	if x != nil {
		return x.StageId
	}
	return 0
}

func (x *AsterLittleDetailInfo) GetStageState() AsterLittleStageState {
	if x != nil {
		return x.StageState
	}
	return AsterLittleStageState_ASTER_LITTLE_STAGE_NONE
}

func (x *AsterLittleDetailInfo) GetStageBeginTime() uint32 {
	if x != nil {
		return x.StageBeginTime
	}
	return 0
}

func (x *AsterLittleDetailInfo) GetBeginTime() uint32 {
	if x != nil {
		return x.BeginTime
	}
	return 0
}

func (x *AsterLittleDetailInfo) GetIsOpen() bool {
	if x != nil {
		return x.IsOpen
	}
	return false
}

var File_AsterLittleDetailInfo_proto protoreflect.FileDescriptor

var file_AsterLittleDetailInfo_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x41, 0x73, 0x74, 0x65, 0x72, 0x4c, 0x69, 0x74, 0x74, 0x6c, 0x65, 0x44, 0x65, 0x74,
	0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x41,
	0x73, 0x74, 0x65, 0x72, 0x4c, 0x69, 0x74, 0x74, 0x6c, 0x65, 0x53, 0x74, 0x61, 0x67, 0x65, 0x53,
	0x74, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xcd, 0x01, 0x0a, 0x15, 0x41,
	0x73, 0x74, 0x65, 0x72, 0x4c, 0x69, 0x74, 0x74, 0x6c, 0x65, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c,
	0x49, 0x6e, 0x66, 0x6f, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x74, 0x61, 0x67, 0x65, 0x5f, 0x69, 0x64,
	0x18, 0x09, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x73, 0x74, 0x61, 0x67, 0x65, 0x49, 0x64, 0x12,
	0x37, 0x0a, 0x0b, 0x73, 0x74, 0x61, 0x67, 0x65, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x65, 0x18, 0x07,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x16, 0x2e, 0x41, 0x73, 0x74, 0x65, 0x72, 0x4c, 0x69, 0x74, 0x74,
	0x6c, 0x65, 0x53, 0x74, 0x61, 0x67, 0x65, 0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x0a, 0x73, 0x74,
	0x61, 0x67, 0x65, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x28, 0x0a, 0x10, 0x73, 0x74, 0x61, 0x67,
	0x65, 0x5f, 0x62, 0x65, 0x67, 0x69, 0x6e, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x0e, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x0e, 0x73, 0x74, 0x61, 0x67, 0x65, 0x42, 0x65, 0x67, 0x69, 0x6e, 0x54, 0x69,
	0x6d, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x62, 0x65, 0x67, 0x69, 0x6e, 0x5f, 0x74, 0x69, 0x6d, 0x65,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x62, 0x65, 0x67, 0x69, 0x6e, 0x54, 0x69, 0x6d,
	0x65, 0x12, 0x17, 0x0a, 0x07, 0x69, 0x73, 0x5f, 0x6f, 0x70, 0x65, 0x6e, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x06, 0x69, 0x73, 0x4f, 0x70, 0x65, 0x6e, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67,
	0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_AsterLittleDetailInfo_proto_rawDescOnce sync.Once
	file_AsterLittleDetailInfo_proto_rawDescData = file_AsterLittleDetailInfo_proto_rawDesc
)

func file_AsterLittleDetailInfo_proto_rawDescGZIP() []byte {
	file_AsterLittleDetailInfo_proto_rawDescOnce.Do(func() {
		file_AsterLittleDetailInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_AsterLittleDetailInfo_proto_rawDescData)
	})
	return file_AsterLittleDetailInfo_proto_rawDescData
}

var file_AsterLittleDetailInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_AsterLittleDetailInfo_proto_goTypes = []interface{}{
	(*AsterLittleDetailInfo)(nil), // 0: AsterLittleDetailInfo
	(AsterLittleStageState)(0),    // 1: AsterLittleStageState
}
var file_AsterLittleDetailInfo_proto_depIdxs = []int32{
	1, // 0: AsterLittleDetailInfo.stage_state:type_name -> AsterLittleStageState
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_AsterLittleDetailInfo_proto_init() }
func file_AsterLittleDetailInfo_proto_init() {
	if File_AsterLittleDetailInfo_proto != nil {
		return
	}
	file_AsterLittleStageState_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_AsterLittleDetailInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AsterLittleDetailInfo); i {
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
			RawDescriptor: file_AsterLittleDetailInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_AsterLittleDetailInfo_proto_goTypes,
		DependencyIndexes: file_AsterLittleDetailInfo_proto_depIdxs,
		MessageInfos:      file_AsterLittleDetailInfo_proto_msgTypes,
	}.Build()
	File_AsterLittleDetailInfo_proto = out.File
	file_AsterLittleDetailInfo_proto_rawDesc = nil
	file_AsterLittleDetailInfo_proto_goTypes = nil
	file_AsterLittleDetailInfo_proto_depIdxs = nil
}
