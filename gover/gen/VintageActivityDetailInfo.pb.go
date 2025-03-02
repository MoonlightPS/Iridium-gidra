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
// source: VintageActivityDetailInfo.proto

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

// Obf: APBBCFJOEOD
type VintageActivityDetailInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IsContentClosed bool                                      `protobuf:"varint,1,opt,name=is_content_closed,json=isContentClosed,proto3" json:"is_content_closed,omitempty"`
	BoothData       *VintageBoothUsedItemData                 `protobuf:"bytes,11,opt,name=booth_data,json=boothData,proto3" json:"booth_data,omitempty"`
	MarketInfo      *VintageMarketInfo                        `protobuf:"bytes,3,opt,name=market_info,json=marketInfo,proto3" json:"market_info,omitempty"`
	CampStageMap    map[uint32]*VintageCampChallengeStageData `protobuf:"bytes,14,rep,name=camp_stage_map,json=campStageMap,proto3" json:"camp_stage_map,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	PresentStageMap map[uint32]*VintagePresentStageData       `protobuf:"bytes,8,rep,name=present_stage_map,json=presentStageMap,proto3" json:"present_stage_map,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	HuntingStageMap map[uint32]*VintageHuntingStageData       `protobuf:"bytes,10,rep,name=hunting_stage_map,json=huntingStageMap,proto3" json:"hunting_stage_map,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *VintageActivityDetailInfo) Reset() {
	*x = VintageActivityDetailInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_VintageActivityDetailInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VintageActivityDetailInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VintageActivityDetailInfo) ProtoMessage() {}

func (x *VintageActivityDetailInfo) ProtoReflect() protoreflect.Message {
	mi := &file_VintageActivityDetailInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VintageActivityDetailInfo.ProtoReflect.Descriptor instead.
func (*VintageActivityDetailInfo) Descriptor() ([]byte, []int) {
	return file_VintageActivityDetailInfo_proto_rawDescGZIP(), []int{0}
}

func (x *VintageActivityDetailInfo) GetIsContentClosed() bool {
	if x != nil {
		return x.IsContentClosed
	}
	return false
}

func (x *VintageActivityDetailInfo) GetBoothData() *VintageBoothUsedItemData {
	if x != nil {
		return x.BoothData
	}
	return nil
}

func (x *VintageActivityDetailInfo) GetMarketInfo() *VintageMarketInfo {
	if x != nil {
		return x.MarketInfo
	}
	return nil
}

func (x *VintageActivityDetailInfo) GetCampStageMap() map[uint32]*VintageCampChallengeStageData {
	if x != nil {
		return x.CampStageMap
	}
	return nil
}

func (x *VintageActivityDetailInfo) GetPresentStageMap() map[uint32]*VintagePresentStageData {
	if x != nil {
		return x.PresentStageMap
	}
	return nil
}

func (x *VintageActivityDetailInfo) GetHuntingStageMap() map[uint32]*VintageHuntingStageData {
	if x != nil {
		return x.HuntingStageMap
	}
	return nil
}

var File_VintageActivityDetailInfo_proto protoreflect.FileDescriptor

var file_VintageActivityDetailInfo_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x56, 0x69, 0x6e, 0x74, 0x61, 0x67, 0x65, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74,
	0x79, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x1e, 0x56, 0x69, 0x6e, 0x74, 0x61, 0x67, 0x65, 0x42, 0x6f, 0x6f, 0x74, 0x68, 0x55,
	0x73, 0x65, 0x64, 0x49, 0x74, 0x65, 0x6d, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x17, 0x56, 0x69, 0x6e, 0x74, 0x61, 0x67, 0x65, 0x4d, 0x61, 0x72, 0x6b, 0x65, 0x74,
	0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x23, 0x56, 0x69, 0x6e, 0x74,
	0x61, 0x67, 0x65, 0x43, 0x61, 0x6d, 0x70, 0x43, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65,
	0x53, 0x74, 0x61, 0x67, 0x65, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x1d, 0x56, 0x69, 0x6e, 0x74, 0x61, 0x67, 0x65, 0x50, 0x72, 0x65, 0x73, 0x65, 0x6e, 0x74, 0x53,
	0x74, 0x61, 0x67, 0x65, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d,
	0x56, 0x69, 0x6e, 0x74, 0x61, 0x67, 0x65, 0x48, 0x75, 0x6e, 0x74, 0x69, 0x6e, 0x67, 0x53, 0x74,
	0x61, 0x67, 0x65, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xe1, 0x05,
	0x0a, 0x19, 0x56, 0x69, 0x6e, 0x74, 0x61, 0x67, 0x65, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74,
	0x79, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x2a, 0x0a, 0x11, 0x69,
	0x73, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x5f, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0f, 0x69, 0x73, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
	0x74, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0x64, 0x12, 0x38, 0x0a, 0x0a, 0x62, 0x6f, 0x6f, 0x74, 0x68,
	0x5f, 0x64, 0x61, 0x74, 0x61, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x56, 0x69,
	0x6e, 0x74, 0x61, 0x67, 0x65, 0x42, 0x6f, 0x6f, 0x74, 0x68, 0x55, 0x73, 0x65, 0x64, 0x49, 0x74,
	0x65, 0x6d, 0x44, 0x61, 0x74, 0x61, 0x52, 0x09, 0x62, 0x6f, 0x6f, 0x74, 0x68, 0x44, 0x61, 0x74,
	0x61, 0x12, 0x33, 0x0a, 0x0b, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x5f, 0x69, 0x6e, 0x66, 0x6f,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x56, 0x69, 0x6e, 0x74, 0x61, 0x67, 0x65,
	0x4d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0a, 0x6d, 0x61, 0x72, 0x6b,
	0x65, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x52, 0x0a, 0x0e, 0x63, 0x61, 0x6d, 0x70, 0x5f, 0x73,
	0x74, 0x61, 0x67, 0x65, 0x5f, 0x6d, 0x61, 0x70, 0x18, 0x0e, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2c,
	0x2e, 0x56, 0x69, 0x6e, 0x74, 0x61, 0x67, 0x65, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79,
	0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x43, 0x61, 0x6d, 0x70, 0x53,
	0x74, 0x61, 0x67, 0x65, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0c, 0x63, 0x61,
	0x6d, 0x70, 0x53, 0x74, 0x61, 0x67, 0x65, 0x4d, 0x61, 0x70, 0x12, 0x5b, 0x0a, 0x11, 0x70, 0x72,
	0x65, 0x73, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x74, 0x61, 0x67, 0x65, 0x5f, 0x6d, 0x61, 0x70, 0x18,
	0x08, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2f, 0x2e, 0x56, 0x69, 0x6e, 0x74, 0x61, 0x67, 0x65, 0x41,
	0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66,
	0x6f, 0x2e, 0x50, 0x72, 0x65, 0x73, 0x65, 0x6e, 0x74, 0x53, 0x74, 0x61, 0x67, 0x65, 0x4d, 0x61,
	0x70, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0f, 0x70, 0x72, 0x65, 0x73, 0x65, 0x6e, 0x74, 0x53,
	0x74, 0x61, 0x67, 0x65, 0x4d, 0x61, 0x70, 0x12, 0x5b, 0x0a, 0x11, 0x68, 0x75, 0x6e, 0x74, 0x69,
	0x6e, 0x67, 0x5f, 0x73, 0x74, 0x61, 0x67, 0x65, 0x5f, 0x6d, 0x61, 0x70, 0x18, 0x0a, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x2f, 0x2e, 0x56, 0x69, 0x6e, 0x74, 0x61, 0x67, 0x65, 0x41, 0x63, 0x74, 0x69,
	0x76, 0x69, 0x74, 0x79, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x48,
	0x75, 0x6e, 0x74, 0x69, 0x6e, 0x67, 0x53, 0x74, 0x61, 0x67, 0x65, 0x4d, 0x61, 0x70, 0x45, 0x6e,
	0x74, 0x72, 0x79, 0x52, 0x0f, 0x68, 0x75, 0x6e, 0x74, 0x69, 0x6e, 0x67, 0x53, 0x74, 0x61, 0x67,
	0x65, 0x4d, 0x61, 0x70, 0x1a, 0x5f, 0x0a, 0x11, 0x43, 0x61, 0x6d, 0x70, 0x53, 0x74, 0x61, 0x67,
	0x65, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x34, 0x0a, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x56, 0x69, 0x6e,
	0x74, 0x61, 0x67, 0x65, 0x43, 0x61, 0x6d, 0x70, 0x43, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67,
	0x65, 0x53, 0x74, 0x61, 0x67, 0x65, 0x44, 0x61, 0x74, 0x61, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a, 0x5c, 0x0a, 0x14, 0x50, 0x72, 0x65, 0x73, 0x65, 0x6e, 0x74,
	0x53, 0x74, 0x61, 0x67, 0x65, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a,
	0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12,
	0x2e, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18,
	0x2e, 0x56, 0x69, 0x6e, 0x74, 0x61, 0x67, 0x65, 0x50, 0x72, 0x65, 0x73, 0x65, 0x6e, 0x74, 0x53,
	0x74, 0x61, 0x67, 0x65, 0x44, 0x61, 0x74, 0x61, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a,
	0x02, 0x38, 0x01, 0x1a, 0x5c, 0x0a, 0x14, 0x48, 0x75, 0x6e, 0x74, 0x69, 0x6e, 0x67, 0x53, 0x74,
	0x61, 0x67, 0x65, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b,
	0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2e, 0x0a,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x56,
	0x69, 0x6e, 0x74, 0x61, 0x67, 0x65, 0x48, 0x75, 0x6e, 0x74, 0x69, 0x6e, 0x67, 0x53, 0x74, 0x61,
	0x67, 0x65, 0x44, 0x61, 0x74, 0x61, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38,
	0x01, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_VintageActivityDetailInfo_proto_rawDescOnce sync.Once
	file_VintageActivityDetailInfo_proto_rawDescData = file_VintageActivityDetailInfo_proto_rawDesc
)

func file_VintageActivityDetailInfo_proto_rawDescGZIP() []byte {
	file_VintageActivityDetailInfo_proto_rawDescOnce.Do(func() {
		file_VintageActivityDetailInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_VintageActivityDetailInfo_proto_rawDescData)
	})
	return file_VintageActivityDetailInfo_proto_rawDescData
}

var file_VintageActivityDetailInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_VintageActivityDetailInfo_proto_goTypes = []interface{}{
	(*VintageActivityDetailInfo)(nil),     // 0: VintageActivityDetailInfo
	nil,                                   // 1: VintageActivityDetailInfo.CampStageMapEntry
	nil,                                   // 2: VintageActivityDetailInfo.PresentStageMapEntry
	nil,                                   // 3: VintageActivityDetailInfo.HuntingStageMapEntry
	(*VintageBoothUsedItemData)(nil),      // 4: VintageBoothUsedItemData
	(*VintageMarketInfo)(nil),             // 5: VintageMarketInfo
	(*VintageCampChallengeStageData)(nil), // 6: VintageCampChallengeStageData
	(*VintagePresentStageData)(nil),       // 7: VintagePresentStageData
	(*VintageHuntingStageData)(nil),       // 8: VintageHuntingStageData
}
var file_VintageActivityDetailInfo_proto_depIdxs = []int32{
	4, // 0: VintageActivityDetailInfo.booth_data:type_name -> VintageBoothUsedItemData
	5, // 1: VintageActivityDetailInfo.market_info:type_name -> VintageMarketInfo
	1, // 2: VintageActivityDetailInfo.camp_stage_map:type_name -> VintageActivityDetailInfo.CampStageMapEntry
	2, // 3: VintageActivityDetailInfo.present_stage_map:type_name -> VintageActivityDetailInfo.PresentStageMapEntry
	3, // 4: VintageActivityDetailInfo.hunting_stage_map:type_name -> VintageActivityDetailInfo.HuntingStageMapEntry
	6, // 5: VintageActivityDetailInfo.CampStageMapEntry.value:type_name -> VintageCampChallengeStageData
	7, // 6: VintageActivityDetailInfo.PresentStageMapEntry.value:type_name -> VintagePresentStageData
	8, // 7: VintageActivityDetailInfo.HuntingStageMapEntry.value:type_name -> VintageHuntingStageData
	8, // [8:8] is the sub-list for method output_type
	8, // [8:8] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_VintageActivityDetailInfo_proto_init() }
func file_VintageActivityDetailInfo_proto_init() {
	if File_VintageActivityDetailInfo_proto != nil {
		return
	}
	file_VintageBoothUsedItemData_proto_init()
	file_VintageMarketInfo_proto_init()
	file_VintageCampChallengeStageData_proto_init()
	file_VintagePresentStageData_proto_init()
	file_VintageHuntingStageData_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_VintageActivityDetailInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VintageActivityDetailInfo); i {
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
			RawDescriptor: file_VintageActivityDetailInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_VintageActivityDetailInfo_proto_goTypes,
		DependencyIndexes: file_VintageActivityDetailInfo_proto_depIdxs,
		MessageInfos:      file_VintageActivityDetailInfo_proto_msgTypes,
	}.Build()
	File_VintageActivityDetailInfo_proto = out.File
	file_VintageActivityDetailInfo_proto_rawDesc = nil
	file_VintageActivityDetailInfo_proto_goTypes = nil
	file_VintageActivityDetailInfo_proto_depIdxs = nil
}
