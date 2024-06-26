/*
*Copyright (c) Alibaba Group;
*Licensed under the Apache License, Version 2.0 (the "License");
*you may not use this file except in compliance with the License.
*You may obtain a copy of the License at

*   http://www.apache.org/licenses/LICENSE-2.0

*Unless required by applicable law or agreed to in writing, software
*distributed under the License is distributed on an "AS IS" BASIS,
*WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*See the License for the specific language governing permissions and
*limitations under the License.
*/

import React from "react";
import {ProFormRadio} from "@ant-design/pro-form";
import {Space} from "antd";
import ProCard from '@ant-design/pro-card';

import {PayChannelEnum} from "@/constants";
import {AlipayCircleOutlined} from "@ant-design/icons";
import {FormattedMessage} from "@@/exports";

const PayTypeFormItem: React.FC = () => {
    const payTypeEntries = Object.entries(PayChannelEnum);

    return (
        <ProFormRadio.Group
            label={'支付方式'}
            name="payChannel"
            initialValue="ALIPAY"
            rules={[{required: true, message: '请选择支付方式'}]}
            rules={[{ required: true, message:  <FormattedMessage id="message.select-payment-method" defaultMessage="请选择支付方式"/>}]}
            options={payTypeEntries.map(([key, value]) => ({
                label: (
                    <Space>
                        {key === 'ALIPAY' && <AlipayCircleOutlined style={{color: '#009fe8'}}/>}
                        {value}
                    </Space>
                ),
                value: key,
            }))}
        />
    );
};
export default PayTypeFormItem;

