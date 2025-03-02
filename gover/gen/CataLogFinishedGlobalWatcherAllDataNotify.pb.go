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
// source: CataLogFinishedGlobalWatcherAllDataNotify.proto

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

// CmdId: 6353
// Obf: EEBGALKIANL
type CataLogFinishedGlobalWatcherAllDataNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	FinishedGlobalWatcherDataList []*CataLogGlobalWatcherFinishedData `protobuf:"bytes,14,rep,name=finished_global_watcher_data_list,json=finishedGlobalWatcherDataList,proto3" json:"finished_global_watcher_data_list,omitempty"`
}

func (x *CataLogFinishedGlobalWatcherAllDataNotify) Reset() {
	*x = CataLogFinishedGlobalWatcherAllDataNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_CataLogFinishedGlobalWatcherAllDataNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CataLogFinishedGlobalWatcherAllDataNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CataLogFinishedGlobalWatcherAllDataNotify) ProtoMessage() {}

func (x *CataLogFinishedGlobalWatcherAllDataNotify) ProtoReflect() protoreflect.Message {
	mi := &file_CataLogFinishedGlobalWatcherAllDataNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CataLogFinishedGlobalWatcherAllDataNotify.ProtoReflect.Descriptor instead.
func (*CataLogFinishedGlobalWatcherAllDataNotify) Descriptor() ([]byte, []int) {
	return file_CataLogFinishedGlobalWatcherAllDataNotify_proto_rawDescGZIP(), []int{0}
}

func (x *CataLogFinishedGlobalWatcherAllDataNotify) GetFinishedGlobalWatcherDataList() []*CataLogGlobalWatcherFinishedData {
	if x != nil {
		return x.FinishedGlobalWatcherDataList
	}
	return nil
}

var File_CataLogFinishedGlobalWatcherAllDataNotify_proto protoreflect.FileDescriptor

var file_CataLogFinishedGlobalWatcherAllDataNotify_proto_rawDesc = []byte{
	0x0a, 0x2f, 0x43, 0x61, 0x74, 0x61, 0x4c, 0x6f, 0x67, 0x46, 0x69, 0x6e, 0x69, 0x73, 0x68, 0x65,
	0x64, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x57, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x41, 0x6c,
	0x6c, 0x44, 0x61, 0x74, 0x61, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x26, 0x43, 0x61, 0x74, 0x61, 0x4c, 0x6f, 0x67, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c,
	0x57, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x46, 0x69, 0x6e, 0x69, 0x73, 0x68, 0x65, 0x64, 0x44,
	0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x98, 0x01, 0x0a, 0x29, 0x43, 0x61,
	0x74, 0x61, 0x4c, 0x6f, 0x67, 0x46, 0x69, 0x6e, 0x69, 0x73, 0x68, 0x65, 0x64, 0x47, 0x6c, 0x6f,
	0x62, 0x61, 0x6c, 0x57, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x41, 0x6c, 0x6c, 0x44, 0x61, 0x74,
	0x61, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x6b, 0x0a, 0x21, 0x66, 0x69, 0x6e, 0x69, 0x73,
	0x68, 0x65, 0x64, 0x5f, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x5f, 0x77, 0x61, 0x74, 0x63, 0x68,
	0x65, 0x72, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0e, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x21, 0x2e, 0x43, 0x61, 0x74, 0x61, 0x4c, 0x6f, 0x67, 0x47, 0x6c, 0x6f, 0x62,
	0x61, 0x6c, 0x57, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x46, 0x69, 0x6e, 0x69, 0x73, 0x68, 0x65,
	0x64, 0x44, 0x61, 0x74, 0x61, 0x52, 0x1d, 0x66, 0x69, 0x6e, 0x69, 0x73, 0x68, 0x65, 0x64, 0x47,
	0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x57, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x44, 0x61, 0x74, 0x61,
	0x4c, 0x69, 0x73, 0x74, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_CataLogFinishedGlobalWatcherAllDataNotify_proto_rawDescOnce sync.Once
	file_CataLogFinishedGlobalWatcherAllDataNotify_proto_rawDescData = file_CataLogFinishedGlobalWatcherAllDataNotify_proto_rawDesc
)

func file_CataLogFinishedGlobalWatcherAllDataNotify_proto_rawDescGZIP() []byte {
	file_CataLogFinishedGlobalWatcherAllDataNotify_proto_rawDescOnce.Do(func() {
		file_CataLogFinishedGlobalWatcherAllDataNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_CataLogFinishedGlobalWatcherAllDataNotify_proto_rawDescData)
	})
	return file_CataLogFinishedGlobalWatcherAllDataNotify_proto_rawDescData
}

var file_CataLogFinishedGlobalWatcherAllDataNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_CataLogFinishedGlobalWatcherAllDataNotify_proto_goTypes = []interface{}{
	(*CataLogFinishedGlobalWatcherAllDataNotify)(nil), // 0: CataLogFinishedGlobalWatcherAllDataNotify
	(*CataLogGlobalWatcherFinishedData)(nil),          // 1: CataLogGlobalWatcherFinishedData
}
var file_CataLogFinishedGlobalWatcherAllDataNotify_proto_depIdxs = []int32{
	1, // 0: CataLogFinishedGlobalWatcherAllDataNotify.finished_global_watcher_data_list:type_name -> CataLogGlobalWatcherFinishedData
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_CataLogFinishedGlobalWatcherAllDataNotify_proto_init() }
func file_CataLogFinishedGlobalWatcherAllDataNotify_proto_init() {
	if File_CataLogFinishedGlobalWatcherAllDataNotify_proto != nil {
		return
	}
	file_CataLogGlobalWatcherFinishedData_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_CataLogFinishedGlobalWatcherAllDataNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CataLogFinishedGlobalWatcherAllDataNotify); i {
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
			RawDescriptor: file_CataLogFinishedGlobalWatcherAllDataNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_CataLogFinishedGlobalWatcherAllDataNotify_proto_goTypes,
		DependencyIndexes: file_CataLogFinishedGlobalWatcherAllDataNotify_proto_depIdxs,
		MessageInfos:      file_CataLogFinishedGlobalWatcherAllDataNotify_proto_msgTypes,
	}.Build()
	File_CataLogFinishedGlobalWatcherAllDataNotify_proto = out.File
	file_CataLogFinishedGlobalWatcherAllDataNotify_proto_rawDesc = nil
	file_CataLogFinishedGlobalWatcherAllDataNotify_proto_goTypes = nil
	file_CataLogFinishedGlobalWatcherAllDataNotify_proto_depIdxs = nil
}
