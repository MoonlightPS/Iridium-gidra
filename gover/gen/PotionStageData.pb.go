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
// source: PotionStageData.proto

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

// Obf: NPKFDGPCMMK
type PotionStageData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LevelList   []*PotionLevelData `protobuf:"bytes,3,rep,name=level_list,json=levelList,proto3" json:"level_list,omitempty"`
	OPPNDAHKFHF []uint32           `protobuf:"varint,7,rep,packed,name=OPPNDAHKFHF,proto3" json:"OPPNDAHKFHF,omitempty"`
	IsOpen      bool               `protobuf:"varint,9,opt,name=is_open,json=isOpen,proto3" json:"is_open,omitempty"`
	StageId     uint32             `protobuf:"varint,14,opt,name=stage_id,json=stageId,proto3" json:"stage_id,omitempty"`
	OCBJDGFPCEP []uint32           `protobuf:"varint,8,rep,packed,name=OCBJDGFPCEP,proto3" json:"OCBJDGFPCEP,omitempty"`
}

func (x *PotionStageData) Reset() {
	*x = PotionStageData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_PotionStageData_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PotionStageData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PotionStageData) ProtoMessage() {}

func (x *PotionStageData) ProtoReflect() protoreflect.Message {
	mi := &file_PotionStageData_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PotionStageData.ProtoReflect.Descriptor instead.
func (*PotionStageData) Descriptor() ([]byte, []int) {
	return file_PotionStageData_proto_rawDescGZIP(), []int{0}
}

func (x *PotionStageData) GetLevelList() []*PotionLevelData {
	if x != nil {
		return x.LevelList
	}
	return nil
}

func (x *PotionStageData) GetOPPNDAHKFHF() []uint32 {
	if x != nil {
		return x.OPPNDAHKFHF
	}
	return nil
}

func (x *PotionStageData) GetIsOpen() bool {
	if x != nil {
		return x.IsOpen
	}
	return false
}

func (x *PotionStageData) GetStageId() uint32 {
	if x != nil {
		return x.StageId
	}
	return 0
}

func (x *PotionStageData) GetOCBJDGFPCEP() []uint32 {
	if x != nil {
		return x.OCBJDGFPCEP
	}
	return nil
}

var File_PotionStageData_proto protoreflect.FileDescriptor

var file_PotionStageData_proto_rawDesc = []byte{
	0x0a, 0x15, 0x50, 0x6f, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x74, 0x61, 0x67, 0x65, 0x44, 0x61, 0x74,
	0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x15, 0x50, 0x6f, 0x74, 0x69, 0x6f, 0x6e, 0x4c,
	0x65, 0x76, 0x65, 0x6c, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xba,
	0x01, 0x0a, 0x0f, 0x50, 0x6f, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x74, 0x61, 0x67, 0x65, 0x44, 0x61,
	0x74, 0x61, 0x12, 0x2f, 0x0a, 0x0a, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x5f, 0x6c, 0x69, 0x73, 0x74,
	0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x50, 0x6f, 0x74, 0x69, 0x6f, 0x6e, 0x4c,
	0x65, 0x76, 0x65, 0x6c, 0x44, 0x61, 0x74, 0x61, 0x52, 0x09, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x4c,
	0x69, 0x73, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x4f, 0x50, 0x50, 0x4e, 0x44, 0x41, 0x48, 0x4b, 0x46,
	0x48, 0x46, 0x18, 0x07, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x0b, 0x4f, 0x50, 0x50, 0x4e, 0x44, 0x41,
	0x48, 0x4b, 0x46, 0x48, 0x46, 0x12, 0x17, 0x0a, 0x07, 0x69, 0x73, 0x5f, 0x6f, 0x70, 0x65, 0x6e,
	0x18, 0x09, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x69, 0x73, 0x4f, 0x70, 0x65, 0x6e, 0x12, 0x19,
	0x0a, 0x08, 0x73, 0x74, 0x61, 0x67, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x07, 0x73, 0x74, 0x61, 0x67, 0x65, 0x49, 0x64, 0x12, 0x20, 0x0a, 0x0b, 0x4f, 0x43, 0x42,
	0x4a, 0x44, 0x47, 0x46, 0x50, 0x43, 0x45, 0x50, 0x18, 0x08, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x0b,
	0x4f, 0x43, 0x42, 0x4a, 0x44, 0x47, 0x46, 0x50, 0x43, 0x45, 0x50, 0x42, 0x06, 0x5a, 0x04, 0x2f,
	0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_PotionStageData_proto_rawDescOnce sync.Once
	file_PotionStageData_proto_rawDescData = file_PotionStageData_proto_rawDesc
)

func file_PotionStageData_proto_rawDescGZIP() []byte {
	file_PotionStageData_proto_rawDescOnce.Do(func() {
		file_PotionStageData_proto_rawDescData = protoimpl.X.CompressGZIP(file_PotionStageData_proto_rawDescData)
	})
	return file_PotionStageData_proto_rawDescData
}

var file_PotionStageData_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_PotionStageData_proto_goTypes = []interface{}{
	(*PotionStageData)(nil), // 0: PotionStageData
	(*PotionLevelData)(nil), // 1: PotionLevelData
}
var file_PotionStageData_proto_depIdxs = []int32{
	1, // 0: PotionStageData.level_list:type_name -> PotionLevelData
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_PotionStageData_proto_init() }
func file_PotionStageData_proto_init() {
	if File_PotionStageData_proto != nil {
		return
	}
	file_PotionLevelData_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_PotionStageData_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PotionStageData); i {
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
			RawDescriptor: file_PotionStageData_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_PotionStageData_proto_goTypes,
		DependencyIndexes: file_PotionStageData_proto_depIdxs,
		MessageInfos:      file_PotionStageData_proto_msgTypes,
	}.Build()
	File_PotionStageData_proto = out.File
	file_PotionStageData_proto_rawDesc = nil
	file_PotionStageData_proto_goTypes = nil
	file_PotionStageData_proto_depIdxs = nil
}
