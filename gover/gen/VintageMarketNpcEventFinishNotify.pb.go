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
// source: VintageMarketNpcEventFinishNotify.proto

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

// CmdId: 24968
// Obf: ELIGGGIBOGD
type VintageMarketNpcEventFinishNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LGCEBJNOBAM        uint32   `protobuf:"varint,13,opt,name=LGCEBJNOBAM,proto3" json:"LGCEBJNOBAM,omitempty"`
	UnlockStrategyList []uint32 `protobuf:"varint,10,rep,packed,name=unlock_strategy_list,json=unlockStrategyList,proto3" json:"unlock_strategy_list,omitempty"`
	LJIOMIABKJC        uint32   `protobuf:"varint,4,opt,name=LJIOMIABKJC,proto3" json:"LJIOMIABKJC,omitempty"`
}

func (x *VintageMarketNpcEventFinishNotify) Reset() {
	*x = VintageMarketNpcEventFinishNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_VintageMarketNpcEventFinishNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VintageMarketNpcEventFinishNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VintageMarketNpcEventFinishNotify) ProtoMessage() {}

func (x *VintageMarketNpcEventFinishNotify) ProtoReflect() protoreflect.Message {
	mi := &file_VintageMarketNpcEventFinishNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VintageMarketNpcEventFinishNotify.ProtoReflect.Descriptor instead.
func (*VintageMarketNpcEventFinishNotify) Descriptor() ([]byte, []int) {
	return file_VintageMarketNpcEventFinishNotify_proto_rawDescGZIP(), []int{0}
}

func (x *VintageMarketNpcEventFinishNotify) GetLGCEBJNOBAM() uint32 {
	if x != nil {
		return x.LGCEBJNOBAM
	}
	return 0
}

func (x *VintageMarketNpcEventFinishNotify) GetUnlockStrategyList() []uint32 {
	if x != nil {
		return x.UnlockStrategyList
	}
	return nil
}

func (x *VintageMarketNpcEventFinishNotify) GetLJIOMIABKJC() uint32 {
	if x != nil {
		return x.LJIOMIABKJC
	}
	return 0
}

var File_VintageMarketNpcEventFinishNotify_proto protoreflect.FileDescriptor

var file_VintageMarketNpcEventFinishNotify_proto_rawDesc = []byte{
	0x0a, 0x27, 0x56, 0x69, 0x6e, 0x74, 0x61, 0x67, 0x65, 0x4d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x4e,
	0x70, 0x63, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x46, 0x69, 0x6e, 0x69, 0x73, 0x68, 0x4e, 0x6f, 0x74,
	0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x99, 0x01, 0x0a, 0x21, 0x56, 0x69,
	0x6e, 0x74, 0x61, 0x67, 0x65, 0x4d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x4e, 0x70, 0x63, 0x45, 0x76,
	0x65, 0x6e, 0x74, 0x46, 0x69, 0x6e, 0x69, 0x73, 0x68, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12,
	0x20, 0x0a, 0x0b, 0x4c, 0x47, 0x43, 0x45, 0x42, 0x4a, 0x4e, 0x4f, 0x42, 0x41, 0x4d, 0x18, 0x0d,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x4c, 0x47, 0x43, 0x45, 0x42, 0x4a, 0x4e, 0x4f, 0x42, 0x41,
	0x4d, 0x12, 0x30, 0x0a, 0x14, 0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x73, 0x74, 0x72, 0x61,
	0x74, 0x65, 0x67, 0x79, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x0d, 0x52,
	0x12, 0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x53, 0x74, 0x72, 0x61, 0x74, 0x65, 0x67, 0x79, 0x4c,
	0x69, 0x73, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x4c, 0x4a, 0x49, 0x4f, 0x4d, 0x49, 0x41, 0x42, 0x4b,
	0x4a, 0x43, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x4c, 0x4a, 0x49, 0x4f, 0x4d, 0x49,
	0x41, 0x42, 0x4b, 0x4a, 0x43, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_VintageMarketNpcEventFinishNotify_proto_rawDescOnce sync.Once
	file_VintageMarketNpcEventFinishNotify_proto_rawDescData = file_VintageMarketNpcEventFinishNotify_proto_rawDesc
)

func file_VintageMarketNpcEventFinishNotify_proto_rawDescGZIP() []byte {
	file_VintageMarketNpcEventFinishNotify_proto_rawDescOnce.Do(func() {
		file_VintageMarketNpcEventFinishNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_VintageMarketNpcEventFinishNotify_proto_rawDescData)
	})
	return file_VintageMarketNpcEventFinishNotify_proto_rawDescData
}

var file_VintageMarketNpcEventFinishNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_VintageMarketNpcEventFinishNotify_proto_goTypes = []interface{}{
	(*VintageMarketNpcEventFinishNotify)(nil), // 0: VintageMarketNpcEventFinishNotify
}
var file_VintageMarketNpcEventFinishNotify_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_VintageMarketNpcEventFinishNotify_proto_init() }
func file_VintageMarketNpcEventFinishNotify_proto_init() {
	if File_VintageMarketNpcEventFinishNotify_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_VintageMarketNpcEventFinishNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VintageMarketNpcEventFinishNotify); i {
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
			RawDescriptor: file_VintageMarketNpcEventFinishNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_VintageMarketNpcEventFinishNotify_proto_goTypes,
		DependencyIndexes: file_VintageMarketNpcEventFinishNotify_proto_depIdxs,
		MessageInfos:      file_VintageMarketNpcEventFinishNotify_proto_msgTypes,
	}.Build()
	File_VintageMarketNpcEventFinishNotify_proto = out.File
	file_VintageMarketNpcEventFinishNotify_proto_rawDesc = nil
	file_VintageMarketNpcEventFinishNotify_proto_goTypes = nil
	file_VintageMarketNpcEventFinishNotify_proto_depIdxs = nil
}
