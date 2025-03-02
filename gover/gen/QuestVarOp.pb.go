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
// source: QuestVarOp.proto

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

// Obf: MKOAOABANJO
type QuestVarOp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Value int32  `protobuf:"varint,14,opt,name=value,proto3" json:"value,omitempty"`
	IsAdd bool   `protobuf:"varint,9,opt,name=is_add,json=isAdd,proto3" json:"is_add,omitempty"`
	Index uint32 `protobuf:"varint,5,opt,name=index,proto3" json:"index,omitempty"`
}

func (x *QuestVarOp) Reset() {
	*x = QuestVarOp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_QuestVarOp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QuestVarOp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QuestVarOp) ProtoMessage() {}

func (x *QuestVarOp) ProtoReflect() protoreflect.Message {
	mi := &file_QuestVarOp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QuestVarOp.ProtoReflect.Descriptor instead.
func (*QuestVarOp) Descriptor() ([]byte, []int) {
	return file_QuestVarOp_proto_rawDescGZIP(), []int{0}
}

func (x *QuestVarOp) GetValue() int32 {
	if x != nil {
		return x.Value
	}
	return 0
}

func (x *QuestVarOp) GetIsAdd() bool {
	if x != nil {
		return x.IsAdd
	}
	return false
}

func (x *QuestVarOp) GetIndex() uint32 {
	if x != nil {
		return x.Index
	}
	return 0
}

var File_QuestVarOp_proto protoreflect.FileDescriptor

var file_QuestVarOp_proto_rawDesc = []byte{
	0x0a, 0x10, 0x51, 0x75, 0x65, 0x73, 0x74, 0x56, 0x61, 0x72, 0x4f, 0x70, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0x4f, 0x0a, 0x0a, 0x51, 0x75, 0x65, 0x73, 0x74, 0x56, 0x61, 0x72, 0x4f, 0x70,
	0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x15, 0x0a, 0x06, 0x69, 0x73, 0x5f, 0x61, 0x64, 0x64,
	0x18, 0x09, 0x20, 0x01, 0x28, 0x08, 0x52, 0x05, 0x69, 0x73, 0x41, 0x64, 0x64, 0x12, 0x14, 0x0a,
	0x05, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x69, 0x6e,
	0x64, 0x65, 0x78, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_QuestVarOp_proto_rawDescOnce sync.Once
	file_QuestVarOp_proto_rawDescData = file_QuestVarOp_proto_rawDesc
)

func file_QuestVarOp_proto_rawDescGZIP() []byte {
	file_QuestVarOp_proto_rawDescOnce.Do(func() {
		file_QuestVarOp_proto_rawDescData = protoimpl.X.CompressGZIP(file_QuestVarOp_proto_rawDescData)
	})
	return file_QuestVarOp_proto_rawDescData
}

var file_QuestVarOp_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_QuestVarOp_proto_goTypes = []interface{}{
	(*QuestVarOp)(nil), // 0: QuestVarOp
}
var file_QuestVarOp_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_QuestVarOp_proto_init() }
func file_QuestVarOp_proto_init() {
	if File_QuestVarOp_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_QuestVarOp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QuestVarOp); i {
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
			RawDescriptor: file_QuestVarOp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_QuestVarOp_proto_goTypes,
		DependencyIndexes: file_QuestVarOp_proto_depIdxs,
		MessageInfos:      file_QuestVarOp_proto_msgTypes,
	}.Build()
	File_QuestVarOp_proto = out.File
	file_QuestVarOp_proto_rawDesc = nil
	file_QuestVarOp_proto_goTypes = nil
	file_QuestVarOp_proto_depIdxs = nil
}
