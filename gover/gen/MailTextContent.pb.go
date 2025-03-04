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
// source: MailTextContent.proto

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

// Obf: CPIHMMKKOIG
type MailTextContent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Title   string `protobuf:"bytes,1,opt,name=title,proto3" json:"title,omitempty"`
	Content string `protobuf:"bytes,2,opt,name=content,proto3" json:"content,omitempty"`
	Sender  string `protobuf:"bytes,3,opt,name=sender,proto3" json:"sender,omitempty"`
}

func (x *MailTextContent) Reset() {
	*x = MailTextContent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_MailTextContent_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MailTextContent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MailTextContent) ProtoMessage() {}

func (x *MailTextContent) ProtoReflect() protoreflect.Message {
	mi := &file_MailTextContent_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MailTextContent.ProtoReflect.Descriptor instead.
func (*MailTextContent) Descriptor() ([]byte, []int) {
	return file_MailTextContent_proto_rawDescGZIP(), []int{0}
}

func (x *MailTextContent) GetTitle() string {
	if x != nil {
		return x.Title
	}
	return ""
}

func (x *MailTextContent) GetContent() string {
	if x != nil {
		return x.Content
	}
	return ""
}

func (x *MailTextContent) GetSender() string {
	if x != nil {
		return x.Sender
	}
	return ""
}

var File_MailTextContent_proto protoreflect.FileDescriptor

var file_MailTextContent_proto_rawDesc = []byte{
	0x0a, 0x15, 0x4d, 0x61, 0x69, 0x6c, 0x54, 0x65, 0x78, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
	0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x59, 0x0a, 0x0f, 0x4d, 0x61, 0x69, 0x6c, 0x54,
	0x65, 0x78, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x69,
	0x74, 0x6c, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x69, 0x74, 0x6c, 0x65,
	0x12, 0x18, 0x0a, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x65,
	0x6e, 0x64, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x65, 0x6e, 0x64,
	0x65, 0x72, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_MailTextContent_proto_rawDescOnce sync.Once
	file_MailTextContent_proto_rawDescData = file_MailTextContent_proto_rawDesc
)

func file_MailTextContent_proto_rawDescGZIP() []byte {
	file_MailTextContent_proto_rawDescOnce.Do(func() {
		file_MailTextContent_proto_rawDescData = protoimpl.X.CompressGZIP(file_MailTextContent_proto_rawDescData)
	})
	return file_MailTextContent_proto_rawDescData
}

var file_MailTextContent_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_MailTextContent_proto_goTypes = []interface{}{
	(*MailTextContent)(nil), // 0: MailTextContent
}
var file_MailTextContent_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_MailTextContent_proto_init() }
func file_MailTextContent_proto_init() {
	if File_MailTextContent_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_MailTextContent_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MailTextContent); i {
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
			RawDescriptor: file_MailTextContent_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_MailTextContent_proto_goTypes,
		DependencyIndexes: file_MailTextContent_proto_depIdxs,
		MessageInfos:      file_MailTextContent_proto_msgTypes,
	}.Build()
	File_MailTextContent_proto = out.File
	file_MailTextContent_proto_rawDesc = nil
	file_MailTextContent_proto_goTypes = nil
	file_MailTextContent_proto_depIdxs = nil
}
