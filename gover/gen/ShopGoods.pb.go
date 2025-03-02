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
// source: ShopGoods.proto

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

// Obf: PIILCEEKMMC
type ShopGoods struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BeginTime        uint32       `protobuf:"varint,14,opt,name=begin_time,json=beginTime,proto3" json:"begin_time,omitempty"`
	APOECIACFPK      uint32       `protobuf:"varint,1474,opt,name=APOECIACFPK,proto3" json:"APOECIACFPK,omitempty"`
	CostItemList     []*ItemParam `protobuf:"bytes,10,rep,name=cost_item_list,json=costItemList,proto3" json:"cost_item_list,omitempty"`
	MaxLevel         uint32       `protobuf:"varint,8,opt,name=max_level,json=maxLevel,proto3" json:"max_level,omitempty"`
	AEBBIJALJCB      uint32       `protobuf:"varint,1508,opt,name=AEBBIJALJCB,proto3" json:"AEBBIJALJCB,omitempty"`
	Scoin            uint32       `protobuf:"varint,12,opt,name=scoin,proto3" json:"scoin,omitempty"`
	Hcoin            uint32       `protobuf:"varint,11,opt,name=hcoin,proto3" json:"hcoin,omitempty"`
	MinLevel         uint32       `protobuf:"varint,13,opt,name=min_level,json=minLevel,proto3" json:"min_level,omitempty"`
	BoughtNum        uint32       `protobuf:"varint,7,opt,name=bought_num,json=boughtNum,proto3" json:"bought_num,omitempty"`
	KINAPHHFNPA      uint32       `protobuf:"varint,256,opt,name=KINAPHHFNPA,proto3" json:"KINAPHHFNPA,omitempty"`
	NextRefreshTime  uint32       `protobuf:"varint,1,opt,name=next_refresh_time,json=nextRefreshTime,proto3" json:"next_refresh_time,omitempty"`
	BuyLimit         uint32       `protobuf:"varint,3,opt,name=buy_limit,json=buyLimit,proto3" json:"buy_limit,omitempty"`
	GoodsItem        *ItemParam   `protobuf:"bytes,6,opt,name=goods_item,json=goodsItem,proto3" json:"goods_item,omitempty"`
	SecondarySheetId uint32       `protobuf:"varint,1819,opt,name=secondary_sheet_id,json=secondarySheetId,proto3" json:"secondary_sheet_id,omitempty"`
	KAPLOLJDEON      uint32       `protobuf:"varint,15,opt,name=KAPLOLJDEON,proto3" json:"KAPLOLJDEON,omitempty"`
	GoodsId          uint32       `protobuf:"varint,9,opt,name=goods_id,json=goodsId,proto3" json:"goods_id,omitempty"`
	EndTime          uint32       `protobuf:"varint,4,opt,name=end_time,json=endTime,proto3" json:"end_time,omitempty"`
	PreGoodsIdList   []uint32     `protobuf:"varint,5,rep,packed,name=preGoodsIdList,proto3" json:"preGoodsIdList,omitempty"`
	IAEPIAMFCPF      uint32       `protobuf:"varint,772,opt,name=IAEPIAMFCPF,proto3" json:"IAEPIAMFCPF,omitempty"`
	Mcoin            uint32       `protobuf:"varint,2,opt,name=mcoin,proto3" json:"mcoin,omitempty"`
}

func (x *ShopGoods) Reset() {
	*x = ShopGoods{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ShopGoods_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ShopGoods) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ShopGoods) ProtoMessage() {}

func (x *ShopGoods) ProtoReflect() protoreflect.Message {
	mi := &file_ShopGoods_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ShopGoods.ProtoReflect.Descriptor instead.
func (*ShopGoods) Descriptor() ([]byte, []int) {
	return file_ShopGoods_proto_rawDescGZIP(), []int{0}
}

func (x *ShopGoods) GetBeginTime() uint32 {
	if x != nil {
		return x.BeginTime
	}
	return 0
}

func (x *ShopGoods) GetAPOECIACFPK() uint32 {
	if x != nil {
		return x.APOECIACFPK
	}
	return 0
}

func (x *ShopGoods) GetCostItemList() []*ItemParam {
	if x != nil {
		return x.CostItemList
	}
	return nil
}

func (x *ShopGoods) GetMaxLevel() uint32 {
	if x != nil {
		return x.MaxLevel
	}
	return 0
}

func (x *ShopGoods) GetAEBBIJALJCB() uint32 {
	if x != nil {
		return x.AEBBIJALJCB
	}
	return 0
}

func (x *ShopGoods) GetScoin() uint32 {
	if x != nil {
		return x.Scoin
	}
	return 0
}

func (x *ShopGoods) GetHcoin() uint32 {
	if x != nil {
		return x.Hcoin
	}
	return 0
}

func (x *ShopGoods) GetMinLevel() uint32 {
	if x != nil {
		return x.MinLevel
	}
	return 0
}

func (x *ShopGoods) GetBoughtNum() uint32 {
	if x != nil {
		return x.BoughtNum
	}
	return 0
}

func (x *ShopGoods) GetKINAPHHFNPA() uint32 {
	if x != nil {
		return x.KINAPHHFNPA
	}
	return 0
}

func (x *ShopGoods) GetNextRefreshTime() uint32 {
	if x != nil {
		return x.NextRefreshTime
	}
	return 0
}

func (x *ShopGoods) GetBuyLimit() uint32 {
	if x != nil {
		return x.BuyLimit
	}
	return 0
}

func (x *ShopGoods) GetGoodsItem() *ItemParam {
	if x != nil {
		return x.GoodsItem
	}
	return nil
}

func (x *ShopGoods) GetSecondarySheetId() uint32 {
	if x != nil {
		return x.SecondarySheetId
	}
	return 0
}

func (x *ShopGoods) GetKAPLOLJDEON() uint32 {
	if x != nil {
		return x.KAPLOLJDEON
	}
	return 0
}

func (x *ShopGoods) GetGoodsId() uint32 {
	if x != nil {
		return x.GoodsId
	}
	return 0
}

func (x *ShopGoods) GetEndTime() uint32 {
	if x != nil {
		return x.EndTime
	}
	return 0
}

func (x *ShopGoods) GetPreGoodsIdList() []uint32 {
	if x != nil {
		return x.PreGoodsIdList
	}
	return nil
}

func (x *ShopGoods) GetIAEPIAMFCPF() uint32 {
	if x != nil {
		return x.IAEPIAMFCPF
	}
	return 0
}

func (x *ShopGoods) GetMcoin() uint32 {
	if x != nil {
		return x.Mcoin
	}
	return 0
}

var File_ShopGoods_proto protoreflect.FileDescriptor

var file_ShopGoods_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x53, 0x68, 0x6f, 0x70, 0x47, 0x6f, 0x6f, 0x64, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x0f, 0x49, 0x74, 0x65, 0x6d, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xa6, 0x05, 0x0a, 0x09, 0x53, 0x68, 0x6f, 0x70, 0x47, 0x6f, 0x6f, 0x64, 0x73,
	0x12, 0x1d, 0x0a, 0x0a, 0x62, 0x65, 0x67, 0x69, 0x6e, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x0e,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x62, 0x65, 0x67, 0x69, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x12,
	0x21, 0x0a, 0x0b, 0x41, 0x50, 0x4f, 0x45, 0x43, 0x49, 0x41, 0x43, 0x46, 0x50, 0x4b, 0x18, 0xc2,
	0x0b, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x41, 0x50, 0x4f, 0x45, 0x43, 0x49, 0x41, 0x43, 0x46,
	0x50, 0x4b, 0x12, 0x30, 0x0a, 0x0e, 0x63, 0x6f, 0x73, 0x74, 0x5f, 0x69, 0x74, 0x65, 0x6d, 0x5f,
	0x6c, 0x69, 0x73, 0x74, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x49, 0x74, 0x65,
	0x6d, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x52, 0x0c, 0x63, 0x6f, 0x73, 0x74, 0x49, 0x74, 0x65, 0x6d,
	0x4c, 0x69, 0x73, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x6d, 0x61, 0x78, 0x5f, 0x6c, 0x65, 0x76, 0x65,
	0x6c, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x6d, 0x61, 0x78, 0x4c, 0x65, 0x76, 0x65,
	0x6c, 0x12, 0x21, 0x0a, 0x0b, 0x41, 0x45, 0x42, 0x42, 0x49, 0x4a, 0x41, 0x4c, 0x4a, 0x43, 0x42,
	0x18, 0xe4, 0x0b, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x41, 0x45, 0x42, 0x42, 0x49, 0x4a, 0x41,
	0x4c, 0x4a, 0x43, 0x42, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x63, 0x6f, 0x69, 0x6e, 0x18, 0x0c, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x05, 0x73, 0x63, 0x6f, 0x69, 0x6e, 0x12, 0x14, 0x0a, 0x05, 0x68, 0x63,
	0x6f, 0x69, 0x6e, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x68, 0x63, 0x6f, 0x69, 0x6e,
	0x12, 0x1b, 0x0a, 0x09, 0x6d, 0x69, 0x6e, 0x5f, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x18, 0x0d, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x08, 0x6d, 0x69, 0x6e, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x12, 0x1d, 0x0a,
	0x0a, 0x62, 0x6f, 0x75, 0x67, 0x68, 0x74, 0x5f, 0x6e, 0x75, 0x6d, 0x18, 0x07, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x09, 0x62, 0x6f, 0x75, 0x67, 0x68, 0x74, 0x4e, 0x75, 0x6d, 0x12, 0x21, 0x0a, 0x0b,
	0x4b, 0x49, 0x4e, 0x41, 0x50, 0x48, 0x48, 0x46, 0x4e, 0x50, 0x41, 0x18, 0x80, 0x02, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x0b, 0x4b, 0x49, 0x4e, 0x41, 0x50, 0x48, 0x48, 0x46, 0x4e, 0x50, 0x41, 0x12,
	0x2a, 0x0a, 0x11, 0x6e, 0x65, 0x78, 0x74, 0x5f, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x5f,
	0x74, 0x69, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0f, 0x6e, 0x65, 0x78, 0x74,
	0x52, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x62,
	0x75, 0x79, 0x5f, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08,
	0x62, 0x75, 0x79, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x12, 0x29, 0x0a, 0x0a, 0x67, 0x6f, 0x6f, 0x64,
	0x73, 0x5f, 0x69, 0x74, 0x65, 0x6d, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x49,
	0x74, 0x65, 0x6d, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x52, 0x09, 0x67, 0x6f, 0x6f, 0x64, 0x73, 0x49,
	0x74, 0x65, 0x6d, 0x12, 0x2d, 0x0a, 0x12, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x61, 0x72, 0x79,
	0x5f, 0x73, 0x68, 0x65, 0x65, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x9b, 0x0e, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x10, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x53, 0x68, 0x65, 0x65, 0x74,
	0x49, 0x64, 0x12, 0x20, 0x0a, 0x0b, 0x4b, 0x41, 0x50, 0x4c, 0x4f, 0x4c, 0x4a, 0x44, 0x45, 0x4f,
	0x4e, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x4b, 0x41, 0x50, 0x4c, 0x4f, 0x4c, 0x4a,
	0x44, 0x45, 0x4f, 0x4e, 0x12, 0x19, 0x0a, 0x08, 0x67, 0x6f, 0x6f, 0x64, 0x73, 0x5f, 0x69, 0x64,
	0x18, 0x09, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x67, 0x6f, 0x6f, 0x64, 0x73, 0x49, 0x64, 0x12,
	0x19, 0x0a, 0x08, 0x65, 0x6e, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x07, 0x65, 0x6e, 0x64, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x26, 0x0a, 0x0e, 0x70, 0x72,
	0x65, 0x47, 0x6f, 0x6f, 0x64, 0x73, 0x49, 0x64, 0x4c, 0x69, 0x73, 0x74, 0x18, 0x05, 0x20, 0x03,
	0x28, 0x0d, 0x52, 0x0e, 0x70, 0x72, 0x65, 0x47, 0x6f, 0x6f, 0x64, 0x73, 0x49, 0x64, 0x4c, 0x69,
	0x73, 0x74, 0x12, 0x21, 0x0a, 0x0b, 0x49, 0x41, 0x45, 0x50, 0x49, 0x41, 0x4d, 0x46, 0x43, 0x50,
	0x46, 0x18, 0x84, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x49, 0x41, 0x45, 0x50, 0x49, 0x41,
	0x4d, 0x46, 0x43, 0x50, 0x46, 0x12, 0x14, 0x0a, 0x05, 0x6d, 0x63, 0x6f, 0x69, 0x6e, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x6d, 0x63, 0x6f, 0x69, 0x6e, 0x42, 0x06, 0x5a, 0x04, 0x2f,
	0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ShopGoods_proto_rawDescOnce sync.Once
	file_ShopGoods_proto_rawDescData = file_ShopGoods_proto_rawDesc
)

func file_ShopGoods_proto_rawDescGZIP() []byte {
	file_ShopGoods_proto_rawDescOnce.Do(func() {
		file_ShopGoods_proto_rawDescData = protoimpl.X.CompressGZIP(file_ShopGoods_proto_rawDescData)
	})
	return file_ShopGoods_proto_rawDescData
}

var file_ShopGoods_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_ShopGoods_proto_goTypes = []interface{}{
	(*ShopGoods)(nil), // 0: ShopGoods
	(*ItemParam)(nil), // 1: ItemParam
}
var file_ShopGoods_proto_depIdxs = []int32{
	1, // 0: ShopGoods.cost_item_list:type_name -> ItemParam
	1, // 1: ShopGoods.goods_item:type_name -> ItemParam
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_ShopGoods_proto_init() }
func file_ShopGoods_proto_init() {
	if File_ShopGoods_proto != nil {
		return
	}
	file_ItemParam_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_ShopGoods_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ShopGoods); i {
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
			RawDescriptor: file_ShopGoods_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ShopGoods_proto_goTypes,
		DependencyIndexes: file_ShopGoods_proto_depIdxs,
		MessageInfos:      file_ShopGoods_proto_msgTypes,
	}.Build()
	File_ShopGoods_proto = out.File
	file_ShopGoods_proto_rawDesc = nil
	file_ShopGoods_proto_goTypes = nil
	file_ShopGoods_proto_depIdxs = nil
}
