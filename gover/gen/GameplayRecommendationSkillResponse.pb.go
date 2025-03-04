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
// source: GameplayRecommendationSkillResponse.proto

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

// Obf: PEEDNDFPNGH
type GameplayRecommendationSkillResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SkillDepotId uint32   `protobuf:"varint,8,opt,name=skill_depot_id,json=skillDepotId,proto3" json:"skill_depot_id,omitempty"`
	SkillIdList  []uint32 `protobuf:"varint,13,rep,packed,name=skill_id_list,json=skillIdList,proto3" json:"skill_id_list,omitempty"`
}

func (x *GameplayRecommendationSkillResponse) Reset() {
	*x = GameplayRecommendationSkillResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GameplayRecommendationSkillResponse_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GameplayRecommendationSkillResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GameplayRecommendationSkillResponse) ProtoMessage() {}

func (x *GameplayRecommendationSkillResponse) ProtoReflect() protoreflect.Message {
	mi := &file_GameplayRecommendationSkillResponse_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GameplayRecommendationSkillResponse.ProtoReflect.Descriptor instead.
func (*GameplayRecommendationSkillResponse) Descriptor() ([]byte, []int) {
	return file_GameplayRecommendationSkillResponse_proto_rawDescGZIP(), []int{0}
}

func (x *GameplayRecommendationSkillResponse) GetSkillDepotId() uint32 {
	if x != nil {
		return x.SkillDepotId
	}
	return 0
}

func (x *GameplayRecommendationSkillResponse) GetSkillIdList() []uint32 {
	if x != nil {
		return x.SkillIdList
	}
	return nil
}

var File_GameplayRecommendationSkillResponse_proto protoreflect.FileDescriptor

var file_GameplayRecommendationSkillResponse_proto_rawDesc = []byte{
	0x0a, 0x29, 0x47, 0x61, 0x6d, 0x65, 0x70, 0x6c, 0x61, 0x79, 0x52, 0x65, 0x63, 0x6f, 0x6d, 0x6d,
	0x65, 0x6e, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x6b, 0x69, 0x6c, 0x6c, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x6f, 0x0a, 0x23, 0x47,
	0x61, 0x6d, 0x65, 0x70, 0x6c, 0x61, 0x79, 0x52, 0x65, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x64,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x6b, 0x69, 0x6c, 0x6c, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x24, 0x0a, 0x0e, 0x73, 0x6b, 0x69, 0x6c, 0x6c, 0x5f, 0x64, 0x65, 0x70, 0x6f,
	0x74, 0x5f, 0x69, 0x64, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0c, 0x73, 0x6b, 0x69, 0x6c,
	0x6c, 0x44, 0x65, 0x70, 0x6f, 0x74, 0x49, 0x64, 0x12, 0x22, 0x0a, 0x0d, 0x73, 0x6b, 0x69, 0x6c,
	0x6c, 0x5f, 0x69, 0x64, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0d, 0x20, 0x03, 0x28, 0x0d, 0x52,
	0x0b, 0x73, 0x6b, 0x69, 0x6c, 0x6c, 0x49, 0x64, 0x4c, 0x69, 0x73, 0x74, 0x42, 0x06, 0x5a, 0x04,
	0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GameplayRecommendationSkillResponse_proto_rawDescOnce sync.Once
	file_GameplayRecommendationSkillResponse_proto_rawDescData = file_GameplayRecommendationSkillResponse_proto_rawDesc
)

func file_GameplayRecommendationSkillResponse_proto_rawDescGZIP() []byte {
	file_GameplayRecommendationSkillResponse_proto_rawDescOnce.Do(func() {
		file_GameplayRecommendationSkillResponse_proto_rawDescData = protoimpl.X.CompressGZIP(file_GameplayRecommendationSkillResponse_proto_rawDescData)
	})
	return file_GameplayRecommendationSkillResponse_proto_rawDescData
}

var file_GameplayRecommendationSkillResponse_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GameplayRecommendationSkillResponse_proto_goTypes = []interface{}{
	(*GameplayRecommendationSkillResponse)(nil), // 0: GameplayRecommendationSkillResponse
}
var file_GameplayRecommendationSkillResponse_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_GameplayRecommendationSkillResponse_proto_init() }
func file_GameplayRecommendationSkillResponse_proto_init() {
	if File_GameplayRecommendationSkillResponse_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_GameplayRecommendationSkillResponse_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GameplayRecommendationSkillResponse); i {
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
			RawDescriptor: file_GameplayRecommendationSkillResponse_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GameplayRecommendationSkillResponse_proto_goTypes,
		DependencyIndexes: file_GameplayRecommendationSkillResponse_proto_depIdxs,
		MessageInfos:      file_GameplayRecommendationSkillResponse_proto_msgTypes,
	}.Build()
	File_GameplayRecommendationSkillResponse_proto = out.File
	file_GameplayRecommendationSkillResponse_proto_rawDesc = nil
	file_GameplayRecommendationSkillResponse_proto_goTypes = nil
	file_GameplayRecommendationSkillResponse_proto_depIdxs = nil
}
