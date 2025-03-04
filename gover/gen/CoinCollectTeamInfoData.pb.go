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
// source: CoinCollectTeamInfoData.proto

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

// Obf: PJFMFEFLOHD
type CoinCollectTeamInfoData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	JFLEEJGJDBJ   []uint32 `protobuf:"varint,4,rep,packed,name=JFLEEJGJDBJ,proto3" json:"JFLEEJGJDBJ,omitempty"`
	ChooseSkillNo uint32   `protobuf:"varint,14,opt,name=choose_skill_no,json=chooseSkillNo,proto3" json:"choose_skill_no,omitempty"`
	PlayerUid     uint32   `protobuf:"varint,3,opt,name=player_uid,json=playerUid,proto3" json:"player_uid,omitempty"`
	HNHLEEPCLEC   []uint32 `protobuf:"varint,5,rep,packed,name=HNHLEEPCLEC,proto3" json:"HNHLEEPCLEC,omitempty"`
	IsHost        bool     `protobuf:"varint,1,opt,name=is_host,json=isHost,proto3" json:"is_host,omitempty"`
	AvatarIdList  []uint32 `protobuf:"varint,6,rep,packed,name=avatar_id_list,json=avatarIdList,proto3" json:"avatar_id_list,omitempty"`
}

func (x *CoinCollectTeamInfoData) Reset() {
	*x = CoinCollectTeamInfoData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_CoinCollectTeamInfoData_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CoinCollectTeamInfoData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CoinCollectTeamInfoData) ProtoMessage() {}

func (x *CoinCollectTeamInfoData) ProtoReflect() protoreflect.Message {
	mi := &file_CoinCollectTeamInfoData_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CoinCollectTeamInfoData.ProtoReflect.Descriptor instead.
func (*CoinCollectTeamInfoData) Descriptor() ([]byte, []int) {
	return file_CoinCollectTeamInfoData_proto_rawDescGZIP(), []int{0}
}

func (x *CoinCollectTeamInfoData) GetJFLEEJGJDBJ() []uint32 {
	if x != nil {
		return x.JFLEEJGJDBJ
	}
	return nil
}

func (x *CoinCollectTeamInfoData) GetChooseSkillNo() uint32 {
	if x != nil {
		return x.ChooseSkillNo
	}
	return 0
}

func (x *CoinCollectTeamInfoData) GetPlayerUid() uint32 {
	if x != nil {
		return x.PlayerUid
	}
	return 0
}

func (x *CoinCollectTeamInfoData) GetHNHLEEPCLEC() []uint32 {
	if x != nil {
		return x.HNHLEEPCLEC
	}
	return nil
}

func (x *CoinCollectTeamInfoData) GetIsHost() bool {
	if x != nil {
		return x.IsHost
	}
	return false
}

func (x *CoinCollectTeamInfoData) GetAvatarIdList() []uint32 {
	if x != nil {
		return x.AvatarIdList
	}
	return nil
}

var File_CoinCollectTeamInfoData_proto protoreflect.FileDescriptor

var file_CoinCollectTeamInfoData_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x43, 0x6f, 0x69, 0x6e, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x54, 0x65, 0x61,
	0x6d, 0x49, 0x6e, 0x66, 0x6f, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0xe3, 0x01, 0x0a, 0x17, 0x43, 0x6f, 0x69, 0x6e, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x54,
	0x65, 0x61, 0x6d, 0x49, 0x6e, 0x66, 0x6f, 0x44, 0x61, 0x74, 0x61, 0x12, 0x20, 0x0a, 0x0b, 0x4a,
	0x46, 0x4c, 0x45, 0x45, 0x4a, 0x47, 0x4a, 0x44, 0x42, 0x4a, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0d,
	0x52, 0x0b, 0x4a, 0x46, 0x4c, 0x45, 0x45, 0x4a, 0x47, 0x4a, 0x44, 0x42, 0x4a, 0x12, 0x26, 0x0a,
	0x0f, 0x63, 0x68, 0x6f, 0x6f, 0x73, 0x65, 0x5f, 0x73, 0x6b, 0x69, 0x6c, 0x6c, 0x5f, 0x6e, 0x6f,
	0x18, 0x0e, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0d, 0x63, 0x68, 0x6f, 0x6f, 0x73, 0x65, 0x53, 0x6b,
	0x69, 0x6c, 0x6c, 0x4e, 0x6f, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x5f,
	0x75, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x70, 0x6c, 0x61, 0x79, 0x65,
	0x72, 0x55, 0x69, 0x64, 0x12, 0x20, 0x0a, 0x0b, 0x48, 0x4e, 0x48, 0x4c, 0x45, 0x45, 0x50, 0x43,
	0x4c, 0x45, 0x43, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x0b, 0x48, 0x4e, 0x48, 0x4c, 0x45,
	0x45, 0x50, 0x43, 0x4c, 0x45, 0x43, 0x12, 0x17, 0x0a, 0x07, 0x69, 0x73, 0x5f, 0x68, 0x6f, 0x73,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x69, 0x73, 0x48, 0x6f, 0x73, 0x74, 0x12,
	0x24, 0x0a, 0x0e, 0x61, 0x76, 0x61, 0x74, 0x61, 0x72, 0x5f, 0x69, 0x64, 0x5f, 0x6c, 0x69, 0x73,
	0x74, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x0c, 0x61, 0x76, 0x61, 0x74, 0x61, 0x72, 0x49,
	0x64, 0x4c, 0x69, 0x73, 0x74, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_CoinCollectTeamInfoData_proto_rawDescOnce sync.Once
	file_CoinCollectTeamInfoData_proto_rawDescData = file_CoinCollectTeamInfoData_proto_rawDesc
)

func file_CoinCollectTeamInfoData_proto_rawDescGZIP() []byte {
	file_CoinCollectTeamInfoData_proto_rawDescOnce.Do(func() {
		file_CoinCollectTeamInfoData_proto_rawDescData = protoimpl.X.CompressGZIP(file_CoinCollectTeamInfoData_proto_rawDescData)
	})
	return file_CoinCollectTeamInfoData_proto_rawDescData
}

var file_CoinCollectTeamInfoData_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_CoinCollectTeamInfoData_proto_goTypes = []interface{}{
	(*CoinCollectTeamInfoData)(nil), // 0: CoinCollectTeamInfoData
}
var file_CoinCollectTeamInfoData_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_CoinCollectTeamInfoData_proto_init() }
func file_CoinCollectTeamInfoData_proto_init() {
	if File_CoinCollectTeamInfoData_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_CoinCollectTeamInfoData_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CoinCollectTeamInfoData); i {
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
			RawDescriptor: file_CoinCollectTeamInfoData_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_CoinCollectTeamInfoData_proto_goTypes,
		DependencyIndexes: file_CoinCollectTeamInfoData_proto_depIdxs,
		MessageInfos:      file_CoinCollectTeamInfoData_proto_msgTypes,
	}.Build()
	File_CoinCollectTeamInfoData_proto = out.File
	file_CoinCollectTeamInfoData_proto_rawDesc = nil
	file_CoinCollectTeamInfoData_proto_goTypes = nil
	file_CoinCollectTeamInfoData_proto_depIdxs = nil
}
