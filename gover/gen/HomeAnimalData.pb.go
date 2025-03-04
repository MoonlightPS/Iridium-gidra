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
// source: HomeAnimalData.proto

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

// Obf: ACFEEBJCEHD
type HomeAnimalData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	FurnitureId uint32  `protobuf:"varint,11,opt,name=furniture_id,json=furnitureId,proto3" json:"furniture_id,omitempty"`
	SpawnRot    *Vector `protobuf:"bytes,10,opt,name=spawnRot,proto3" json:"spawnRot,omitempty"`
	SpawnPos    *Vector `protobuf:"bytes,4,opt,name=spawn_pos,json=spawnPos,proto3" json:"spawn_pos,omitempty"`
}

func (x *HomeAnimalData) Reset() {
	*x = HomeAnimalData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_HomeAnimalData_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HomeAnimalData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HomeAnimalData) ProtoMessage() {}

func (x *HomeAnimalData) ProtoReflect() protoreflect.Message {
	mi := &file_HomeAnimalData_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HomeAnimalData.ProtoReflect.Descriptor instead.
func (*HomeAnimalData) Descriptor() ([]byte, []int) {
	return file_HomeAnimalData_proto_rawDescGZIP(), []int{0}
}

func (x *HomeAnimalData) GetFurnitureId() uint32 {
	if x != nil {
		return x.FurnitureId
	}
	return 0
}

func (x *HomeAnimalData) GetSpawnRot() *Vector {
	if x != nil {
		return x.SpawnRot
	}
	return nil
}

func (x *HomeAnimalData) GetSpawnPos() *Vector {
	if x != nil {
		return x.SpawnPos
	}
	return nil
}

var File_HomeAnimalData_proto protoreflect.FileDescriptor

var file_HomeAnimalData_proto_rawDesc = []byte{
	0x0a, 0x14, 0x48, 0x6f, 0x6d, 0x65, 0x41, 0x6e, 0x69, 0x6d, 0x61, 0x6c, 0x44, 0x61, 0x74, 0x61,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0c, 0x56, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0x7e, 0x0a, 0x0e, 0x48, 0x6f, 0x6d, 0x65, 0x41, 0x6e, 0x69, 0x6d,
	0x61, 0x6c, 0x44, 0x61, 0x74, 0x61, 0x12, 0x21, 0x0a, 0x0c, 0x66, 0x75, 0x72, 0x6e, 0x69, 0x74,
	0x75, 0x72, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x66, 0x75,
	0x72, 0x6e, 0x69, 0x74, 0x75, 0x72, 0x65, 0x49, 0x64, 0x12, 0x23, 0x0a, 0x08, 0x73, 0x70, 0x61,
	0x77, 0x6e, 0x52, 0x6f, 0x74, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x07, 0x2e, 0x56, 0x65,
	0x63, 0x74, 0x6f, 0x72, 0x52, 0x08, 0x73, 0x70, 0x61, 0x77, 0x6e, 0x52, 0x6f, 0x74, 0x12, 0x24,
	0x0a, 0x09, 0x73, 0x70, 0x61, 0x77, 0x6e, 0x5f, 0x70, 0x6f, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x07, 0x2e, 0x56, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x52, 0x08, 0x73, 0x70, 0x61, 0x77,
	0x6e, 0x50, 0x6f, 0x73, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_HomeAnimalData_proto_rawDescOnce sync.Once
	file_HomeAnimalData_proto_rawDescData = file_HomeAnimalData_proto_rawDesc
)

func file_HomeAnimalData_proto_rawDescGZIP() []byte {
	file_HomeAnimalData_proto_rawDescOnce.Do(func() {
		file_HomeAnimalData_proto_rawDescData = protoimpl.X.CompressGZIP(file_HomeAnimalData_proto_rawDescData)
	})
	return file_HomeAnimalData_proto_rawDescData
}

var file_HomeAnimalData_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_HomeAnimalData_proto_goTypes = []interface{}{
	(*HomeAnimalData)(nil), // 0: HomeAnimalData
	(*Vector)(nil),         // 1: Vector
}
var file_HomeAnimalData_proto_depIdxs = []int32{
	1, // 0: HomeAnimalData.spawnRot:type_name -> Vector
	1, // 1: HomeAnimalData.spawn_pos:type_name -> Vector
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_HomeAnimalData_proto_init() }
func file_HomeAnimalData_proto_init() {
	if File_HomeAnimalData_proto != nil {
		return
	}
	file_Vector_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_HomeAnimalData_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HomeAnimalData); i {
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
			RawDescriptor: file_HomeAnimalData_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_HomeAnimalData_proto_goTypes,
		DependencyIndexes: file_HomeAnimalData_proto_depIdxs,
		MessageInfos:      file_HomeAnimalData_proto_msgTypes,
	}.Build()
	File_HomeAnimalData_proto = out.File
	file_HomeAnimalData_proto_rawDesc = nil
	file_HomeAnimalData_proto_goTypes = nil
	file_HomeAnimalData_proto_depIdxs = nil
}
