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
package org.example.common.param.payment;

import lombok.Data;
import org.example.common.constant.PayChannel;
import org.example.common.constant.PayPeriodUnit;

@Data
public class CreateTransactionParam {

    /**
     * order id for alipay or wechat
     */
    private String orderId;

    /**
     * pay channel
     */
    private PayChannel payChannel;
}
