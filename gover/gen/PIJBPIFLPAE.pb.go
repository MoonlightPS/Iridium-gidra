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
// source: PIJBPIFLPAE.proto

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

type PIJBPIFLPAE struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	HNGKHBALOLP uint32   `protobuf:"varint,6,opt,name=HNGKHBALOLP,proto3" json:"HNGKHBALOLP,omitempty"`
	Phase       uint32   `protobuf:"varint,13,opt,name=phase,proto3" json:"phase,omitempty"`
	BIHDGIPJMGC uint32   `protobuf:"varint,12,opt,name=BIHDGIPJMGC,proto3" json:"BIHDGIPJMGC,omitempty"`
	FNDEEPLICMM uint32   `protobuf:"varint,9,opt,name=FNDEEPLICMM,proto3" json:"FNDEEPLICMM,omitempty"`
	HMJEPKDPGAP uint32   `protobuf:"varint,2,opt,name=HMJEPKDPGAP,proto3" json:"HMJEPKDPGAP,omitempty"`
	HHPNADNCEOK []uint32 `protobuf:"varint,4,rep,packed,name=HHPNADNCEOK,proto3" json:"HHPNADNCEOK,omitempty"`
}

func (x *PIJBPIFLPAE) Reset() {
	*x = PIJBPIFLPAE{}
	if protoimpl.UnsafeEnabled {
		mi := &file_PIJBPIFLPAE_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PIJBPIFLPAE) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PIJBPIFLPAE) ProtoMessage() {}

func (x *PIJBPIFLPAE) ProtoReflect() protoreflect.Message {
	mi := &file_PIJBPIFLPAE_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PIJBPIFLPAE.ProtoReflect.Descriptor instead.
func (*PIJBPIFLPAE) Descriptor() ([]byte, []int) {
	return file_PIJBPIFLPAE_proto_rawDescGZIP(), []int{0}
}

func (x *PIJBPIFLPAE) GetHNGKHBALOLP() uint32 {
	if x != nil {
		return x.HNGKHBALOLP
	}
	return 0
}

func (x *PIJBPIFLPAE) GetPhase() uint32 {
	if x != nil {
		return x.Phase
	}
	return 0
}

func (x *PIJBPIFLPAE) GetBIHDGIPJMGC() uint32 {
	if x != nil {
		return x.BIHDGIPJMGC
	}
	return 0
}

func (x *PIJBPIFLPAE) GetFNDEEPLICMM() uint32 {
	if x != nil {
		return x.FNDEEPLICMM
	}
	return 0
}

func (x *PIJBPIFLPAE) GetHMJEPKDPGAP() uint32 {
	if x != nil {
		return x.HMJEPKDPGAP
	}
	return 0
}

func (x *PIJBPIFLPAE) GetHHPNADNCEOK() []uint32 {
	if x != nil {
		return x.HHPNADNCEOK
	}
	return nil
}

var File_PIJBPIFLPAE_proto protoreflect.FileDescriptor

var file_PIJBPIFLPAE_proto_rawDesc = []byte{
	0x0a, 0x11, 0x50, 0x49, 0x4a, 0x42, 0x50, 0x49, 0x46, 0x4c, 0x50, 0x41, 0x45, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0xcd, 0x01, 0x0a, 0x0b, 0x50, 0x49, 0x4a, 0x42, 0x50, 0x49, 0x46, 0x4c,
	0x50, 0x41, 0x45, 0x12, 0x20, 0x0a, 0x0b, 0x48, 0x4e, 0x47, 0x4b, 0x48, 0x42, 0x41, 0x4c, 0x4f,
	0x4c, 0x50, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x48, 0x4e, 0x47, 0x4b, 0x48, 0x42,
	0x41, 0x4c, 0x4f, 0x4c, 0x50, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x68, 0x61, 0x73, 0x65, 0x18, 0x0d,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x70, 0x68, 0x61, 0x73, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x42,
	0x49, 0x48, 0x44, 0x47, 0x49, 0x50, 0x4a, 0x4d, 0x47, 0x43, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x0b, 0x42, 0x49, 0x48, 0x44, 0x47, 0x49, 0x50, 0x4a, 0x4d, 0x47, 0x43, 0x12, 0x20, 0x0a,
	0x0b, 0x46, 0x4e, 0x44, 0x45, 0x45, 0x50, 0x4c, 0x49, 0x43, 0x4d, 0x4d, 0x18, 0x09, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x0b, 0x46, 0x4e, 0x44, 0x45, 0x45, 0x50, 0x4c, 0x49, 0x43, 0x4d, 0x4d, 0x12,
	0x20, 0x0a, 0x0b, 0x48, 0x4d, 0x4a, 0x45, 0x50, 0x4b, 0x44, 0x50, 0x47, 0x41, 0x50, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x48, 0x4d, 0x4a, 0x45, 0x50, 0x4b, 0x44, 0x50, 0x47, 0x41,
	0x50, 0x12, 0x20, 0x0a, 0x0b, 0x48, 0x48, 0x50, 0x4e, 0x41, 0x44, 0x4e, 0x43, 0x45, 0x4f, 0x4b,
	0x18, 0x04, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x0b, 0x48, 0x48, 0x50, 0x4e, 0x41, 0x44, 0x4e, 0x43,
	0x45, 0x4f, 0x4b, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_PIJBPIFLPAE_proto_rawDescOnce sync.Once
	file_PIJBPIFLPAE_proto_rawDescData = file_PIJBPIFLPAE_proto_rawDesc
)

func file_PIJBPIFLPAE_proto_rawDescGZIP() []byte {
	file_PIJBPIFLPAE_proto_rawDescOnce.Do(func() {
		file_PIJBPIFLPAE_proto_rawDescData = protoimpl.X.CompressGZIP(file_PIJBPIFLPAE_proto_rawDescData)
	})
	return file_PIJBPIFLPAE_proto_rawDescData
}

var file_PIJBPIFLPAE_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_PIJBPIFLPAE_proto_goTypes = []interface{}{
	(*PIJBPIFLPAE)(nil), // 0: PIJBPIFLPAE
}
var file_PIJBPIFLPAE_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_PIJBPIFLPAE_proto_init() }
func file_PIJBPIFLPAE_proto_init() {
	if File_PIJBPIFLPAE_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_PIJBPIFLPAE_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PIJBPIFLPAE); i {
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
			RawDescriptor: file_PIJBPIFLPAE_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_PIJBPIFLPAE_proto_goTypes,
		DependencyIndexes: file_PIJBPIFLPAE_proto_depIdxs,
		MessageInfos:      file_PIJBPIFLPAE_proto_msgTypes,
	}.Build()
	File_PIJBPIFLPAE_proto = out.File
	file_PIJBPIFLPAE_proto_rawDesc = nil
	file_PIJBPIFLPAE_proto_goTypes = nil
	file_PIJBPIFLPAE_proto_depIdxs = nil
}
