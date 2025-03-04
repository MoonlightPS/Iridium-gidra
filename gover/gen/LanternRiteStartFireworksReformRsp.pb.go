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
// source: LanternRiteStartFireworksReformRsp.proto

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

// CmdId: 8260
// Obf: MNFKALOFEIO
type LanternRiteStartFireworksReformRsp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MBEGNNPJAPL    uint32                                  `protobuf:"varint,12,opt,name=MBEGNNPJAPL,proto3" json:"MBEGNNPJAPL,omitempty"`
	Retcode        int32                                   `protobuf:"varint,8,opt,name=retcode,proto3" json:"retcode,omitempty"`
	SkillInfoList  []*LanternRiteFireworksReformSkillInfo  `protobuf:"bytes,1,rep,name=skill_info_list,json=skillInfoList,proto3" json:"skill_info_list,omitempty"`
	DKBBJDIMJPB    uint32                                  `protobuf:"varint,10,opt,name=DKBBJDIMJPB,proto3" json:"DKBBJDIMJPB,omitempty"`
	FactorInfoList []*LanternRiteFireworksReformFactorInfo `protobuf:"bytes,6,rep,name=factor_info_list,json=factorInfoList,proto3" json:"factor_info_list,omitempty"`
	JGLNDBHIAPK    uint32                                  `protobuf:"varint,9,opt,name=JGLNDBHIAPK,proto3" json:"JGLNDBHIAPK,omitempty"`
	FCGOPINPKBP    uint32                                  `protobuf:"varint,3,opt,name=FCGOPINPKBP,proto3" json:"FCGOPINPKBP,omitempty"`
	ChallengeId    uint32                                  `protobuf:"varint,13,opt,name=challenge_id,json=challengeId,proto3" json:"challenge_id,omitempty"`
	StageId        uint32                                  `protobuf:"varint,14,opt,name=stage_id,json=stageId,proto3" json:"stage_id,omitempty"`
}

func (x *LanternRiteStartFireworksReformRsp) Reset() {
	*x = LanternRiteStartFireworksReformRsp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_LanternRiteStartFireworksReformRsp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LanternRiteStartFireworksReformRsp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LanternRiteStartFireworksReformRsp) ProtoMessage() {}

func (x *LanternRiteStartFireworksReformRsp) ProtoReflect() protoreflect.Message {
	mi := &file_LanternRiteStartFireworksReformRsp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LanternRiteStartFireworksReformRsp.ProtoReflect.Descriptor instead.
func (*LanternRiteStartFireworksReformRsp) Descriptor() ([]byte, []int) {
	return file_LanternRiteStartFireworksReformRsp_proto_rawDescGZIP(), []int{0}
}

func (x *LanternRiteStartFireworksReformRsp) GetMBEGNNPJAPL() uint32 {
	if x != nil {
		return x.MBEGNNPJAPL
	}
	return 0
}

func (x *LanternRiteStartFireworksReformRsp) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

func (x *LanternRiteStartFireworksReformRsp) GetSkillInfoList() []*LanternRiteFireworksReformSkillInfo {
	if x != nil {
		return x.SkillInfoList
	}
	return nil
}

func (x *LanternRiteStartFireworksReformRsp) GetDKBBJDIMJPB() uint32 {
	if x != nil {
		return x.DKBBJDIMJPB
	}
	return 0
}

func (x *LanternRiteStartFireworksReformRsp) GetFactorInfoList() []*LanternRiteFireworksReformFactorInfo {
	if x != nil {
		return x.FactorInfoList
	}
	return nil
}

func (x *LanternRiteStartFireworksReformRsp) GetJGLNDBHIAPK() uint32 {
	if x != nil {
		return x.JGLNDBHIAPK
	}
	return 0
}

func (x *LanternRiteStartFireworksReformRsp) GetFCGOPINPKBP() uint32 {
	if x != nil {
		return x.FCGOPINPKBP
	}
	return 0
}

func (x *LanternRiteStartFireworksReformRsp) GetChallengeId() uint32 {
	if x != nil {
		return x.ChallengeId
	}
	return 0
}

func (x *LanternRiteStartFireworksReformRsp) GetStageId() uint32 {
	if x != nil {
		return x.StageId
	}
	return 0
}

var File_LanternRiteStartFireworksReformRsp_proto protoreflect.FileDescriptor

var file_LanternRiteStartFireworksReformRsp_proto_rawDesc = []byte{
	0x0a, 0x28, 0x4c, 0x61, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x52, 0x69, 0x74, 0x65, 0x53, 0x74, 0x61,
	0x72, 0x74, 0x46, 0x69, 0x72, 0x65, 0x77, 0x6f, 0x72, 0x6b, 0x73, 0x52, 0x65, 0x66, 0x6f, 0x72,
	0x6d, 0x52, 0x73, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x29, 0x4c, 0x61, 0x6e, 0x74,
	0x65, 0x72, 0x6e, 0x52, 0x69, 0x74, 0x65, 0x46, 0x69, 0x72, 0x65, 0x77, 0x6f, 0x72, 0x6b, 0x73,
	0x52, 0x65, 0x66, 0x6f, 0x72, 0x6d, 0x53, 0x6b, 0x69, 0x6c, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2a, 0x4c, 0x61, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x52, 0x69,
	0x74, 0x65, 0x46, 0x69, 0x72, 0x65, 0x77, 0x6f, 0x72, 0x6b, 0x73, 0x52, 0x65, 0x66, 0x6f, 0x72,
	0x6d, 0x46, 0x61, 0x63, 0x74, 0x6f, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0xa3, 0x03, 0x0a, 0x22, 0x4c, 0x61, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x52, 0x69, 0x74,
	0x65, 0x53, 0x74, 0x61, 0x72, 0x74, 0x46, 0x69, 0x72, 0x65, 0x77, 0x6f, 0x72, 0x6b, 0x73, 0x52,
	0x65, 0x66, 0x6f, 0x72, 0x6d, 0x52, 0x73, 0x70, 0x12, 0x20, 0x0a, 0x0b, 0x4d, 0x42, 0x45, 0x47,
	0x4e, 0x4e, 0x50, 0x4a, 0x41, 0x50, 0x4c, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x4d,
	0x42, 0x45, 0x47, 0x4e, 0x4e, 0x50, 0x4a, 0x41, 0x50, 0x4c, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x65,
	0x74, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x05, 0x52, 0x07, 0x72, 0x65, 0x74,
	0x63, 0x6f, 0x64, 0x65, 0x12, 0x4c, 0x0a, 0x0f, 0x73, 0x6b, 0x69, 0x6c, 0x6c, 0x5f, 0x69, 0x6e,
	0x66, 0x6f, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x24, 0x2e,
	0x4c, 0x61, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x52, 0x69, 0x74, 0x65, 0x46, 0x69, 0x72, 0x65, 0x77,
	0x6f, 0x72, 0x6b, 0x73, 0x52, 0x65, 0x66, 0x6f, 0x72, 0x6d, 0x53, 0x6b, 0x69, 0x6c, 0x6c, 0x49,
	0x6e, 0x66, 0x6f, 0x52, 0x0d, 0x73, 0x6b, 0x69, 0x6c, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x4c, 0x69,
	0x73, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x44, 0x4b, 0x42, 0x42, 0x4a, 0x44, 0x49, 0x4d, 0x4a, 0x50,
	0x42, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x44, 0x4b, 0x42, 0x42, 0x4a, 0x44, 0x49,
	0x4d, 0x4a, 0x50, 0x42, 0x12, 0x4f, 0x0a, 0x10, 0x66, 0x61, 0x63, 0x74, 0x6f, 0x72, 0x5f, 0x69,
	0x6e, 0x66, 0x6f, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x25,
	0x2e, 0x4c, 0x61, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x52, 0x69, 0x74, 0x65, 0x46, 0x69, 0x72, 0x65,
	0x77, 0x6f, 0x72, 0x6b, 0x73, 0x52, 0x65, 0x66, 0x6f, 0x72, 0x6d, 0x46, 0x61, 0x63, 0x74, 0x6f,
	0x72, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0e, 0x66, 0x61, 0x63, 0x74, 0x6f, 0x72, 0x49, 0x6e, 0x66,
	0x6f, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x4a, 0x47, 0x4c, 0x4e, 0x44, 0x42, 0x48,
	0x49, 0x41, 0x50, 0x4b, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x4a, 0x47, 0x4c, 0x4e,
	0x44, 0x42, 0x48, 0x49, 0x41, 0x50, 0x4b, 0x12, 0x20, 0x0a, 0x0b, 0x46, 0x43, 0x47, 0x4f, 0x50,
	0x49, 0x4e, 0x50, 0x4b, 0x42, 0x50, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x46, 0x43,
	0x47, 0x4f, 0x50, 0x49, 0x4e, 0x50, 0x4b, 0x42, 0x50, 0x12, 0x21, 0x0a, 0x0c, 0x63, 0x68, 0x61,
	0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x0b, 0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x49, 0x64, 0x12, 0x19, 0x0a, 0x08,
	0x73, 0x74, 0x61, 0x67, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07,
	0x73, 0x74, 0x61, 0x67, 0x65, 0x49, 0x64, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_LanternRiteStartFireworksReformRsp_proto_rawDescOnce sync.Once
	file_LanternRiteStartFireworksReformRsp_proto_rawDescData = file_LanternRiteStartFireworksReformRsp_proto_rawDesc
)

func file_LanternRiteStartFireworksReformRsp_proto_rawDescGZIP() []byte {
	file_LanternRiteStartFireworksReformRsp_proto_rawDescOnce.Do(func() {
		file_LanternRiteStartFireworksReformRsp_proto_rawDescData = protoimpl.X.CompressGZIP(file_LanternRiteStartFireworksReformRsp_proto_rawDescData)
	})
	return file_LanternRiteStartFireworksReformRsp_proto_rawDescData
}

var file_LanternRiteStartFireworksReformRsp_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_LanternRiteStartFireworksReformRsp_proto_goTypes = []interface{}{
	(*LanternRiteStartFireworksReformRsp)(nil),   // 0: LanternRiteStartFireworksReformRsp
	(*LanternRiteFireworksReformSkillInfo)(nil),  // 1: LanternRiteFireworksReformSkillInfo
	(*LanternRiteFireworksReformFactorInfo)(nil), // 2: LanternRiteFireworksReformFactorInfo
}
var file_LanternRiteStartFireworksReformRsp_proto_depIdxs = []int32{
	1, // 0: LanternRiteStartFireworksReformRsp.skill_info_list:type_name -> LanternRiteFireworksReformSkillInfo
	2, // 1: LanternRiteStartFireworksReformRsp.factor_info_list:type_name -> LanternRiteFireworksReformFactorInfo
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_LanternRiteStartFireworksReformRsp_proto_init() }
func file_LanternRiteStartFireworksReformRsp_proto_init() {
	if File_LanternRiteStartFireworksReformRsp_proto != nil {
		return
	}
	file_LanternRiteFireworksReformSkillInfo_proto_init()
	file_LanternRiteFireworksReformFactorInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_LanternRiteStartFireworksReformRsp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LanternRiteStartFireworksReformRsp); i {
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
			RawDescriptor: file_LanternRiteStartFireworksReformRsp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_LanternRiteStartFireworksReformRsp_proto_goTypes,
		DependencyIndexes: file_LanternRiteStartFireworksReformRsp_proto_depIdxs,
		MessageInfos:      file_LanternRiteStartFireworksReformRsp_proto_msgTypes,
	}.Build()
	File_LanternRiteStartFireworksReformRsp_proto = out.File
	file_LanternRiteStartFireworksReformRsp_proto_rawDesc = nil
	file_LanternRiteStartFireworksReformRsp_proto_goTypes = nil
	file_LanternRiteStartFireworksReformRsp_proto_depIdxs = nil
}
