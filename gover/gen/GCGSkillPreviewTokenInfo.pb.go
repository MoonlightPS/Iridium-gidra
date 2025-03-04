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
// source: GCGSkillPreviewTokenInfo.proto

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

// Obf: NDMOFEBNCGM
type GCGSkillPreviewTokenInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	JAGENMHHAPJ uint32 `protobuf:"varint,9,opt,name=JAGENMHHAPJ,proto3" json:"JAGENMHHAPJ,omitempty"`
	KKPBODKKDGK uint32 `protobuf:"varint,4,opt,name=KKPBODKKDGK,proto3" json:"KKPBODKKDGK,omitempty"`
	FIGGLGDEGIG uint32 `protobuf:"varint,14,opt,name=FIGGLGDEGIG,proto3" json:"FIGGLGDEGIG,omitempty"`
}

func (x *GCGSkillPreviewTokenInfo) Reset() {
	*x = GCGSkillPreviewTokenInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GCGSkillPreviewTokenInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GCGSkillPreviewTokenInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GCGSkillPreviewTokenInfo) ProtoMessage() {}

func (x *GCGSkillPreviewTokenInfo) ProtoReflect() protoreflect.Message {
	mi := &file_GCGSkillPreviewTokenInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GCGSkillPreviewTokenInfo.ProtoReflect.Descriptor instead.
func (*GCGSkillPreviewTokenInfo) Descriptor() ([]byte, []int) {
	return file_GCGSkillPreviewTokenInfo_proto_rawDescGZIP(), []int{0}
}

func (x *GCGSkillPreviewTokenInfo) GetJAGENMHHAPJ() uint32 {
	if x != nil {
		return x.JAGENMHHAPJ
	}
	return 0
}

func (x *GCGSkillPreviewTokenInfo) GetKKPBODKKDGK() uint32 {
	if x != nil {
		return x.KKPBODKKDGK
	}
	return 0
}

func (x *GCGSkillPreviewTokenInfo) GetFIGGLGDEGIG() uint32 {
	if x != nil {
		return x.FIGGLGDEGIG
	}
	return 0
}

var File_GCGSkillPreviewTokenInfo_proto protoreflect.FileDescriptor

var file_GCGSkillPreviewTokenInfo_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x47, 0x43, 0x47, 0x53, 0x6b, 0x69, 0x6c, 0x6c, 0x50, 0x72, 0x65, 0x76, 0x69, 0x65,
	0x77, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0x80, 0x01, 0x0a, 0x18, 0x47, 0x43, 0x47, 0x53, 0x6b, 0x69, 0x6c, 0x6c, 0x50, 0x72, 0x65,
	0x76, 0x69, 0x65, 0x77, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x20, 0x0a,
	0x0b, 0x4a, 0x41, 0x47, 0x45, 0x4e, 0x4d, 0x48, 0x48, 0x41, 0x50, 0x4a, 0x18, 0x09, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x0b, 0x4a, 0x41, 0x47, 0x45, 0x4e, 0x4d, 0x48, 0x48, 0x41, 0x50, 0x4a, 0x12,
	0x20, 0x0a, 0x0b, 0x4b, 0x4b, 0x50, 0x42, 0x4f, 0x44, 0x4b, 0x4b, 0x44, 0x47, 0x4b, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x4b, 0x4b, 0x50, 0x42, 0x4f, 0x44, 0x4b, 0x4b, 0x44, 0x47,
	0x4b, 0x12, 0x20, 0x0a, 0x0b, 0x46, 0x49, 0x47, 0x47, 0x4c, 0x47, 0x44, 0x45, 0x47, 0x49, 0x47,
	0x18, 0x0e, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x46, 0x49, 0x47, 0x47, 0x4c, 0x47, 0x44, 0x45,
	0x47, 0x49, 0x47, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_GCGSkillPreviewTokenInfo_proto_rawDescOnce sync.Once
	file_GCGSkillPreviewTokenInfo_proto_rawDescData = file_GCGSkillPreviewTokenInfo_proto_rawDesc
)

func file_GCGSkillPreviewTokenInfo_proto_rawDescGZIP() []byte {
	file_GCGSkillPreviewTokenInfo_proto_rawDescOnce.Do(func() {
		file_GCGSkillPreviewTokenInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_GCGSkillPreviewTokenInfo_proto_rawDescData)
	})
	return file_GCGSkillPreviewTokenInfo_proto_rawDescData
}

var file_GCGSkillPreviewTokenInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GCGSkillPreviewTokenInfo_proto_goTypes = []interface{}{
	(*GCGSkillPreviewTokenInfo)(nil), // 0: GCGSkillPreviewTokenInfo
}
var file_GCGSkillPreviewTokenInfo_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_GCGSkillPreviewTokenInfo_proto_init() }
func file_GCGSkillPreviewTokenInfo_proto_init() {
	if File_GCGSkillPreviewTokenInfo_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_GCGSkillPreviewTokenInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GCGSkillPreviewTokenInfo); i {
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
			RawDescriptor: file_GCGSkillPreviewTokenInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GCGSkillPreviewTokenInfo_proto_goTypes,
		DependencyIndexes: file_GCGSkillPreviewTokenInfo_proto_depIdxs,
		MessageInfos:      file_GCGSkillPreviewTokenInfo_proto_msgTypes,
	}.Build()
	File_GCGSkillPreviewTokenInfo_proto = out.File
	file_GCGSkillPreviewTokenInfo_proto_rawDesc = nil
	file_GCGSkillPreviewTokenInfo_proto_goTypes = nil
	file_GCGSkillPreviewTokenInfo_proto_depIdxs = nil
}
