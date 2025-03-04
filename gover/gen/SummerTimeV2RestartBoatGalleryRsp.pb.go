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
// source: SummerTimeV2RestartBoatGalleryRsp.proto

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

// CmdId: 8166
// Obf: KLELJLCDPHF
type SummerTimeV2RestartBoatGalleryRsp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Retcode   int32  `protobuf:"varint,6,opt,name=retcode,proto3" json:"retcode,omitempty"`
	GalleryId uint32 `protobuf:"varint,2,opt,name=gallery_id,json=galleryId,proto3" json:"gallery_id,omitempty"`
}

func (x *SummerTimeV2RestartBoatGalleryRsp) Reset() {
	*x = SummerTimeV2RestartBoatGalleryRsp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_SummerTimeV2RestartBoatGalleryRsp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SummerTimeV2RestartBoatGalleryRsp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SummerTimeV2RestartBoatGalleryRsp) ProtoMessage() {}

func (x *SummerTimeV2RestartBoatGalleryRsp) ProtoReflect() protoreflect.Message {
	mi := &file_SummerTimeV2RestartBoatGalleryRsp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SummerTimeV2RestartBoatGalleryRsp.ProtoReflect.Descriptor instead.
func (*SummerTimeV2RestartBoatGalleryRsp) Descriptor() ([]byte, []int) {
	return file_SummerTimeV2RestartBoatGalleryRsp_proto_rawDescGZIP(), []int{0}
}

func (x *SummerTimeV2RestartBoatGalleryRsp) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

func (x *SummerTimeV2RestartBoatGalleryRsp) GetGalleryId() uint32 {
	if x != nil {
		return x.GalleryId
	}
	return 0
}

var File_SummerTimeV2RestartBoatGalleryRsp_proto protoreflect.FileDescriptor

var file_SummerTimeV2RestartBoatGalleryRsp_proto_rawDesc = []byte{
	0x0a, 0x27, 0x53, 0x75, 0x6d, 0x6d, 0x65, 0x72, 0x54, 0x69, 0x6d, 0x65, 0x56, 0x32, 0x52, 0x65,
	0x73, 0x74, 0x61, 0x72, 0x74, 0x42, 0x6f, 0x61, 0x74, 0x47, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79,
	0x52, 0x73, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x5c, 0x0a, 0x21, 0x53, 0x75, 0x6d,
	0x6d, 0x65, 0x72, 0x54, 0x69, 0x6d, 0x65, 0x56, 0x32, 0x52, 0x65, 0x73, 0x74, 0x61, 0x72, 0x74,
	0x42, 0x6f, 0x61, 0x74, 0x47, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79, 0x52, 0x73, 0x70, 0x12, 0x18,
	0x0a, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x67, 0x61, 0x6c, 0x6c,
	0x65, 0x72, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x67, 0x61,
	0x6c, 0x6c, 0x65, 0x72, 0x79, 0x49, 0x64, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_SummerTimeV2RestartBoatGalleryRsp_proto_rawDescOnce sync.Once
	file_SummerTimeV2RestartBoatGalleryRsp_proto_rawDescData = file_SummerTimeV2RestartBoatGalleryRsp_proto_rawDesc
)

func file_SummerTimeV2RestartBoatGalleryRsp_proto_rawDescGZIP() []byte {
	file_SummerTimeV2RestartBoatGalleryRsp_proto_rawDescOnce.Do(func() {
		file_SummerTimeV2RestartBoatGalleryRsp_proto_rawDescData = protoimpl.X.CompressGZIP(file_SummerTimeV2RestartBoatGalleryRsp_proto_rawDescData)
	})
	return file_SummerTimeV2RestartBoatGalleryRsp_proto_rawDescData
}

var file_SummerTimeV2RestartBoatGalleryRsp_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_SummerTimeV2RestartBoatGalleryRsp_proto_goTypes = []interface{}{
	(*SummerTimeV2RestartBoatGalleryRsp)(nil), // 0: SummerTimeV2RestartBoatGalleryRsp
}
var file_SummerTimeV2RestartBoatGalleryRsp_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_SummerTimeV2RestartBoatGalleryRsp_proto_init() }
func file_SummerTimeV2RestartBoatGalleryRsp_proto_init() {
	if File_SummerTimeV2RestartBoatGalleryRsp_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_SummerTimeV2RestartBoatGalleryRsp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SummerTimeV2RestartBoatGalleryRsp); i {
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
			RawDescriptor: file_SummerTimeV2RestartBoatGalleryRsp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_SummerTimeV2RestartBoatGalleryRsp_proto_goTypes,
		DependencyIndexes: file_SummerTimeV2RestartBoatGalleryRsp_proto_depIdxs,
		MessageInfos:      file_SummerTimeV2RestartBoatGalleryRsp_proto_msgTypes,
	}.Build()
	File_SummerTimeV2RestartBoatGalleryRsp_proto = out.File
	file_SummerTimeV2RestartBoatGalleryRsp_proto_rawDesc = nil
	file_SummerTimeV2RestartBoatGalleryRsp_proto_goTypes = nil
	file_SummerTimeV2RestartBoatGalleryRsp_proto_depIdxs = nil
}
