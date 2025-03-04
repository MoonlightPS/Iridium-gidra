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
// source: ActivityAcceptGiftResultInfo.proto

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

// Obf: EJKDFCMJLEE
type ActivityAcceptGiftResultInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BLNMJKEKMKN map[uint32]uint32 `protobuf:"bytes,1,rep,name=BLNMJKEKMKN,proto3" json:"BLNMJKEKMKN,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3"`
	DCNCHKBMNOA map[uint32]uint32 `protobuf:"bytes,5,rep,name=DCNCHKBMNOA,proto3" json:"DCNCHKBMNOA,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3"`
	Uid         uint32            `protobuf:"varint,14,opt,name=uid,proto3" json:"uid,omitempty"`
}

func (x *ActivityAcceptGiftResultInfo) Reset() {
	*x = ActivityAcceptGiftResultInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ActivityAcceptGiftResultInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ActivityAcceptGiftResultInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ActivityAcceptGiftResultInfo) ProtoMessage() {}

func (x *ActivityAcceptGiftResultInfo) ProtoReflect() protoreflect.Message {
	mi := &file_ActivityAcceptGiftResultInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ActivityAcceptGiftResultInfo.ProtoReflect.Descriptor instead.
func (*ActivityAcceptGiftResultInfo) Descriptor() ([]byte, []int) {
	return file_ActivityAcceptGiftResultInfo_proto_rawDescGZIP(), []int{0}
}

func (x *ActivityAcceptGiftResultInfo) GetBLNMJKEKMKN() map[uint32]uint32 {
	if x != nil {
		return x.BLNMJKEKMKN
	}
	return nil
}

func (x *ActivityAcceptGiftResultInfo) GetDCNCHKBMNOA() map[uint32]uint32 {
	if x != nil {
		return x.DCNCHKBMNOA
	}
	return nil
}

func (x *ActivityAcceptGiftResultInfo) GetUid() uint32 {
	if x != nil {
		return x.Uid
	}
	return 0
}

var File_ActivityAcceptGiftResultInfo_proto protoreflect.FileDescriptor

var file_ActivityAcceptGiftResultInfo_proto_rawDesc = []byte{
	0x0a, 0x22, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74,
	0x47, 0x69, 0x66, 0x74, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xd4, 0x02, 0x0a, 0x1c, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74,
	0x79, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x47, 0x69, 0x66, 0x74, 0x52, 0x65, 0x73, 0x75, 0x6c,
	0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x50, 0x0a, 0x0b, 0x42, 0x4c, 0x4e, 0x4d, 0x4a, 0x4b, 0x45,
	0x4b, 0x4d, 0x4b, 0x4e, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2e, 0x2e, 0x41, 0x63, 0x74,
	0x69, 0x76, 0x69, 0x74, 0x79, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x47, 0x69, 0x66, 0x74, 0x52,
	0x65, 0x73, 0x75, 0x6c, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x42, 0x4c, 0x4e, 0x4d, 0x4a, 0x4b,
	0x45, 0x4b, 0x4d, 0x4b, 0x4e, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0b, 0x42, 0x4c, 0x4e, 0x4d,
	0x4a, 0x4b, 0x45, 0x4b, 0x4d, 0x4b, 0x4e, 0x12, 0x50, 0x0a, 0x0b, 0x44, 0x43, 0x4e, 0x43, 0x48,
	0x4b, 0x42, 0x4d, 0x4e, 0x4f, 0x41, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2e, 0x2e, 0x41,
	0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x47, 0x69, 0x66,
	0x74, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x44, 0x43, 0x4e, 0x43,
	0x48, 0x4b, 0x42, 0x4d, 0x4e, 0x4f, 0x41, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0b, 0x44, 0x43,
	0x4e, 0x43, 0x48, 0x4b, 0x42, 0x4d, 0x4e, 0x4f, 0x41, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x69, 0x64,
	0x18, 0x0e, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x75, 0x69, 0x64, 0x1a, 0x3e, 0x0a, 0x10, 0x42,
	0x4c, 0x4e, 0x4d, 0x4a, 0x4b, 0x45, 0x4b, 0x4d, 0x4b, 0x4e, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12,
	0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x6b, 0x65,
	0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a, 0x3e, 0x0a, 0x10, 0x44,
	0x43, 0x4e, 0x43, 0x48, 0x4b, 0x42, 0x4d, 0x4e, 0x4f, 0x41, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12,
	0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x6b, 0x65,
	0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x06, 0x5a, 0x04, 0x2f,
	0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ActivityAcceptGiftResultInfo_proto_rawDescOnce sync.Once
	file_ActivityAcceptGiftResultInfo_proto_rawDescData = file_ActivityAcceptGiftResultInfo_proto_rawDesc
)

func file_ActivityAcceptGiftResultInfo_proto_rawDescGZIP() []byte {
	file_ActivityAcceptGiftResultInfo_proto_rawDescOnce.Do(func() {
		file_ActivityAcceptGiftResultInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_ActivityAcceptGiftResultInfo_proto_rawDescData)
	})
	return file_ActivityAcceptGiftResultInfo_proto_rawDescData
}

var file_ActivityAcceptGiftResultInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_ActivityAcceptGiftResultInfo_proto_goTypes = []interface{}{
	(*ActivityAcceptGiftResultInfo)(nil), // 0: ActivityAcceptGiftResultInfo
	nil,                                  // 1: ActivityAcceptGiftResultInfo.BLNMJKEKMKNEntry
	nil,                                  // 2: ActivityAcceptGiftResultInfo.DCNCHKBMNOAEntry
}
var file_ActivityAcceptGiftResultInfo_proto_depIdxs = []int32{
	1, // 0: ActivityAcceptGiftResultInfo.BLNMJKEKMKN:type_name -> ActivityAcceptGiftResultInfo.BLNMJKEKMKNEntry
	2, // 1: ActivityAcceptGiftResultInfo.DCNCHKBMNOA:type_name -> ActivityAcceptGiftResultInfo.DCNCHKBMNOAEntry
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_ActivityAcceptGiftResultInfo_proto_init() }
func file_ActivityAcceptGiftResultInfo_proto_init() {
	if File_ActivityAcceptGiftResultInfo_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_ActivityAcceptGiftResultInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ActivityAcceptGiftResultInfo); i {
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
			RawDescriptor: file_ActivityAcceptGiftResultInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ActivityAcceptGiftResultInfo_proto_goTypes,
		DependencyIndexes: file_ActivityAcceptGiftResultInfo_proto_depIdxs,
		MessageInfos:      file_ActivityAcceptGiftResultInfo_proto_msgTypes,
	}.Build()
	File_ActivityAcceptGiftResultInfo_proto = out.File
	file_ActivityAcceptGiftResultInfo_proto_rawDesc = nil
	file_ActivityAcceptGiftResultInfo_proto_goTypes = nil
	file_ActivityAcceptGiftResultInfo_proto_depIdxs = nil
}
