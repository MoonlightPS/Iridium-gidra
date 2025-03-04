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
// source: CustomDungeonAbstract.proto

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

// Obf: ECHELFAJJKI
type CustomDungeonAbstract struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BrickStatisticsMap map[uint32]uint32 `protobuf:"bytes,5,rep,name=brick_statistics_map,json=brickStatisticsMap,proto3" json:"brick_statistics_map,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3"`
	FirstPublishTime   uint32            `protobuf:"varint,10,opt,name=first_publish_time,json=firstPublishTime,proto3" json:"first_publish_time,omitempty"`
	HKDPKCOMKPK        uint32            `protobuf:"varint,8,opt,name=HKDPKCOMKPK,proto3" json:"HKDPKCOMKPK,omitempty"`
	LastPublishTime    uint32            `protobuf:"varint,2,opt,name=last_publish_time,json=lastPublishTime,proto3" json:"last_publish_time,omitempty"`
	MJAOONEPHPL        uint32            `protobuf:"varint,12,opt,name=MJAOONEPHPL,proto3" json:"MJAOONEPHPL,omitempty"`
}

func (x *CustomDungeonAbstract) Reset() {
	*x = CustomDungeonAbstract{}
	if protoimpl.UnsafeEnabled {
		mi := &file_CustomDungeonAbstract_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CustomDungeonAbstract) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CustomDungeonAbstract) ProtoMessage() {}

func (x *CustomDungeonAbstract) ProtoReflect() protoreflect.Message {
	mi := &file_CustomDungeonAbstract_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CustomDungeonAbstract.ProtoReflect.Descriptor instead.
func (*CustomDungeonAbstract) Descriptor() ([]byte, []int) {
	return file_CustomDungeonAbstract_proto_rawDescGZIP(), []int{0}
}

func (x *CustomDungeonAbstract) GetBrickStatisticsMap() map[uint32]uint32 {
	if x != nil {
		return x.BrickStatisticsMap
	}
	return nil
}

func (x *CustomDungeonAbstract) GetFirstPublishTime() uint32 {
	if x != nil {
		return x.FirstPublishTime
	}
	return 0
}

func (x *CustomDungeonAbstract) GetHKDPKCOMKPK() uint32 {
	if x != nil {
		return x.HKDPKCOMKPK
	}
	return 0
}

func (x *CustomDungeonAbstract) GetLastPublishTime() uint32 {
	if x != nil {
		return x.LastPublishTime
	}
	return 0
}

func (x *CustomDungeonAbstract) GetMJAOONEPHPL() uint32 {
	if x != nil {
		return x.MJAOONEPHPL
	}
	return 0
}

var File_CustomDungeonAbstract_proto protoreflect.FileDescriptor

var file_CustomDungeonAbstract_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x41,
	0x62, 0x73, 0x74, 0x72, 0x61, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xde, 0x02,
	0x0a, 0x15, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x41,
	0x62, 0x73, 0x74, 0x72, 0x61, 0x63, 0x74, 0x12, 0x60, 0x0a, 0x14, 0x62, 0x72, 0x69, 0x63, 0x6b,
	0x5f, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x73, 0x5f, 0x6d, 0x61, 0x70, 0x18,
	0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2e, 0x2e, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x44, 0x75,
	0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x41, 0x62, 0x73, 0x74, 0x72, 0x61, 0x63, 0x74, 0x2e, 0x42, 0x72,
	0x69, 0x63, 0x6b, 0x53, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x73, 0x4d, 0x61, 0x70,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x12, 0x62, 0x72, 0x69, 0x63, 0x6b, 0x53, 0x74, 0x61, 0x74,
	0x69, 0x73, 0x74, 0x69, 0x63, 0x73, 0x4d, 0x61, 0x70, 0x12, 0x2c, 0x0a, 0x12, 0x66, 0x69, 0x72,
	0x73, 0x74, 0x5f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18,
	0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x10, 0x66, 0x69, 0x72, 0x73, 0x74, 0x50, 0x75, 0x62, 0x6c,
	0x69, 0x73, 0x68, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x48, 0x4b, 0x44, 0x50, 0x4b,
	0x43, 0x4f, 0x4d, 0x4b, 0x50, 0x4b, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x48, 0x4b,
	0x44, 0x50, 0x4b, 0x43, 0x4f, 0x4d, 0x4b, 0x50, 0x4b, 0x12, 0x2a, 0x0a, 0x11, 0x6c, 0x61, 0x73,
	0x74, 0x5f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x0f, 0x6c, 0x61, 0x73, 0x74, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x73,
	0x68, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x4d, 0x4a, 0x41, 0x4f, 0x4f, 0x4e, 0x45,
	0x50, 0x48, 0x50, 0x4c, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x4d, 0x4a, 0x41, 0x4f,
	0x4f, 0x4e, 0x45, 0x50, 0x48, 0x50, 0x4c, 0x1a, 0x45, 0x0a, 0x17, 0x42, 0x72, 0x69, 0x63, 0x6b,
	0x53, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x73, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x06,
	0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_CustomDungeonAbstract_proto_rawDescOnce sync.Once
	file_CustomDungeonAbstract_proto_rawDescData = file_CustomDungeonAbstract_proto_rawDesc
)

func file_CustomDungeonAbstract_proto_rawDescGZIP() []byte {
	file_CustomDungeonAbstract_proto_rawDescOnce.Do(func() {
		file_CustomDungeonAbstract_proto_rawDescData = protoimpl.X.CompressGZIP(file_CustomDungeonAbstract_proto_rawDescData)
	})
	return file_CustomDungeonAbstract_proto_rawDescData
}

var file_CustomDungeonAbstract_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_CustomDungeonAbstract_proto_goTypes = []interface{}{
	(*CustomDungeonAbstract)(nil), // 0: CustomDungeonAbstract
	nil,                           // 1: CustomDungeonAbstract.BrickStatisticsMapEntry
}
var file_CustomDungeonAbstract_proto_depIdxs = []int32{
	1, // 0: CustomDungeonAbstract.brick_statistics_map:type_name -> CustomDungeonAbstract.BrickStatisticsMapEntry
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_CustomDungeonAbstract_proto_init() }
func file_CustomDungeonAbstract_proto_init() {
	if File_CustomDungeonAbstract_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_CustomDungeonAbstract_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CustomDungeonAbstract); i {
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
			RawDescriptor: file_CustomDungeonAbstract_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_CustomDungeonAbstract_proto_goTypes,
		DependencyIndexes: file_CustomDungeonAbstract_proto_depIdxs,
		MessageInfos:      file_CustomDungeonAbstract_proto_msgTypes,
	}.Build()
	File_CustomDungeonAbstract_proto = out.File
	file_CustomDungeonAbstract_proto_rawDesc = nil
	file_CustomDungeonAbstract_proto_goTypes = nil
	file_CustomDungeonAbstract_proto_depIdxs = nil
}
