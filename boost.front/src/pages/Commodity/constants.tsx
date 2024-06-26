import {ProColumns} from '@ant-design/pro-table';
import {ProForm, ProFormDigit, ProFormSelect, ProFormText} from "@ant-design/pro-form";
import React, {ReactNode} from "react";
import {Button, message, Space} from "antd";
import {CopyOutlined} from "@ant-design/icons";
import copy from 'copy-to-clipboard';

export const commodityColumns: ProColumns<API.CommodityDTO>[] = [
    {
        title: '商品码',
        dataIndex: 'commodityCode',
        key: 'commodityCode',
        search: false,
        render: (dom: ReactNode, record: API.CommodityDTO, index: number) => {
            const text = dom as string;
            return (
                <>
                    {text}
                    <Button
                        type="text"
                        size="small"
                        icon={<CopyOutlined/>}
                        onClick={() => {
                            copy(text);
                            message.success('商品码已复制到剪贴板');
                        }}
                    />
                </>
            );
        }
    },
    {
        title: '商品名',
        dataIndex: 'commodityName',
        key: 'commodityName',
        search: false,
    },
    {
        title: '计算巢服务ID',
        dataIndex: 'serviceId',
        key: 'serviceId',
        search: false,
    },
    {
        title: '商品默认价格',
        dataIndex: 'unitPrice',
        key: 'unitPrice',
        search: false,
    },
    {
        title: '商品描述',
        dataIndex: 'description',
        key: 'description',
        search: false,
        hideInTable: true
    },
    {
        title: '状态',
        dataIndex: 'commodityStatus',
        key: 'commodityStatus',
        search: false,
        hideInTable: true
    },
    {
        title: '支付周期单位',
        dataIndex: 'payPeriodUnit',
        key: 'payPeriodUnit',
        valueType: 'text',
        search: false
    },
    {
        title: '支持的售卖周期',
        dataIndex: 'payPeriods',
        key: 'payPeriods',
        valueType: 'text',
        search: false

    },
];

export interface CommodityFormProps {
    commodity: API.CommodityDTO | undefined;
    onSubmit: (values: API.CommodityDTO) => Promise<void>;

    onCancel: () => void;
}

export const CommodityForm: React.FC<CommodityFormProps> = ({commodity, onSubmit, onCancel}) => {
    return (
        <ProForm<API.CommodityDTO>
            onFinish={onSubmit}
            onFinishFailed={(errorInfo) => {
                console.log(errorInfo);
                message.error('Failed to submit commodity');
            }}
            submitter={{
                render: (_, dom) => (
                    <>
                        <Space size={"small"}>
                            <Button
                                onClick={() => {
                                    onCancel();
                                }}
                            >
                                取消
                            </Button>
                            {dom[1]}
                        </Space>

                    </>
                ),
            }}
            initialValues={commodity || {}}
        >
            {commodity?.commodityCode && (
                <ProFormText
                    name="commodityCode"
                    label="商品码"
                    disabled={true}
                    rules={[{required: true, message: 'Please input commodity code!'}]}

                />
            )}
            <ProFormText
                name="commodityName"
                label="商品名"
                rules={[{required: true, message: 'Please input commodity name!'}]}
            />
            <ProFormText
                name="serviceId"
                label="计算巢服务ID"
                rules={[{required: true, message: 'Please input service ID!'},
                    () => ({
                        validator(_, value) {
                            if (!value || value.startsWith("service-")) {
                                return Promise.resolve();
                            }
                            return Promise.reject(new Error('服务ID必须以 "service-"开始'));
                        },
                    }),]}
            />
            <ProFormDigit
                name="unitPrice"
                label="默认价格"
                fieldProps={{precision: 2}}
                min={0}
                rules={[{required: true, message: 'Please input unit price!'}]}
            />
            <ProFormText
                name="description"
                label="描述"
                rules={[{required: true, message: 'Please input service ID!'}]}
            />
            <ProFormSelect
                name="payPeriodUnit"
                label="单位购买周期"
                options={[
                    {label: '月', value: 'Month'},
                    {label: '日', value: 'Day'},
                    {label: '年', value: 'Year'}
                ]}
                rules={[{required: true, message: 'Please select pay period unit!'}]}
            />
            <ProFormSelect
                name="payPeriods"
                label="允许购买的周期"
                mode="multiple"
                options={Array.from({length: 12}, (_, i) => ({label: (i + 1).toString(), value: i + 1}))}
                fieldProps={{
                    optionFilterProp: "children",
                    filterOption: (input, option) => {
                        const childrenString = typeof option?.children === 'string' ? option.children : '';
                        return childrenString.toLowerCase().indexOf(input.toLowerCase()) >= 0;
                    }
                }}
                rules={[{required: true, message: 'Please select pay periods!'}]}
            />
            {!commodity?.commodityCode && (<ProFormSelect
                name="chargeType"
                label="付费方式"
                options={[
                    {label: '包年包月', value: "PrePaid"},
                ]}
                rules={[{required: true, message: 'Please select charge type!'}]}
            />)}
        </ProForm>
    );
};


export const specificationColumns: ProColumns<API.CommoditySpecificationDTO>[] = [
    {
        title: '套餐名',
        dataIndex: 'specificationName',
        key: 'specificationName',
        valueType: 'text',
        search: false

    },
    {
        title: '支付周期单位',
        dataIndex: 'payPeriodUnit',
        key: 'payPeriodUnit',
        valueType: 'text',
        search: false
    },
    {
        title: '支持的售卖周期',
        dataIndex: 'payPeriods',
        key: 'payPeriods',
        valueType: 'text',
        search: false

    },

    {
        title: '单价',
        dataIndex: 'unitPrice',
        key: 'unitPrice',
        valueType: 'money',
        search: false,
    },
    {
        title: '币种',
        dataIndex: 'currency',
        key: 'currency',
        valueType: 'text',
        search: false,
    },
];

export interface SpecificationModalProps {
    commodity: API.CommodityDTO;
    visible: boolean;
    onClose: () => void;
}

interface SpecificationFormProps {
    initialValues?: API.CommoditySpecificationDTO | undefined;
    onSubmit: (values: API.CreateCommoditySpecificationParam | API.UpdateCommoditySpecificationParam) => Promise<void>;

    onCancel: () => void

}

export const SpecificationForm: React.FC<SpecificationFormProps> = ({
                                                                        initialValues,
                                                                        onSubmit,
                                                                        onCancel
                                                                    }) => {


    return (
        <ProForm<API.CreateCommoditySpecificationParam>
            onFinish={onSubmit}
            onFinishFailed={(errorInfo) => {
                console.log(errorInfo);
            }}
            submitter={{
                render: (_, dom) => (
                    <>
                        <Space size={"small"}>
                            <Button
                                onClick={() => {
                                    onCancel();
                                }}
                            >
                                取消
                            </Button>
                            {dom[1]}
                        </Space>

                    </>
                ),
            }}
            initialValues={initialValues}
        >
            {<ProFormText
                name="specificationName"
                label="套餐名"
                rules={[{required: true, message: 'Please input specification name!'}]}
                disabled={initialValues != undefined && initialValues?.commodityCode != undefined}
            />}
            <ProFormDigit
                name="unitPrice"
                label="单价"
                fieldProps={{precision: 2}}
                min={0}
                rules={[{required: true, message: 'Please input unit price!'}]}
            />
            <ProFormSelect
                name="payPeriodUnit"
                label="单位购买周期"
                options={[
                    {label: '月', value: 'Month'},
                    {label: '日', value: 'Day'},
                    {label: '年', value: 'Year'}
                ]}
                rules={[{required: true, message: 'Please select pay period unit!'}]}
            />
            <ProFormSelect
                name="payPeriods"
                label="允许购买的周期"
                mode="multiple"
                options={Array.from({length: 12}, (_, i) => ({label: (i + 1).toString(), value: i + 1}))}
                fieldProps={{
                    optionFilterProp: "children",
                    filterOption: (input, option) => {
                        const childrenString = typeof option?.children === 'string' ? option.children : '';
                        return childrenString.toLowerCase().indexOf(input.toLowerCase()) >= 0;
                    }
                }}
                rules={[{required: true, message: 'Please select pay periods!'}]}
            />
            <ProFormSelect
                name="currency"
                label="Currency"
                hidden={true}
                initialValue={"CNY"}
                fieldProps={{
                    defaultValue: "CNY"
                }}
                options={[
                    {label: 'CNY', value: 'CNY'}
                ]}
            />
        </ProForm>
    );
}
