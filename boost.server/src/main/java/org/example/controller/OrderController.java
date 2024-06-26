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

package org.example.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.example.common.BaseResult;
import org.example.common.ListResult;
import org.example.common.SPI;
import org.example.common.dto.OrderDTO;
import org.example.common.model.UserInfoModel;
import org.example.common.param.order.CreateOrderParam;
import org.example.common.param.order.GetOrderParam;
import org.example.common.param.order.ListOrdersParam;
import org.example.common.param.order.RefundOrderParam;
import org.example.service.order.OrderService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import springfox.documentation.annotations.ApiIgnore;

import javax.annotation.Resource;
import javax.validation.Valid;

@Slf4j
@RestController
@RequestMapping("/api")
@Api(value="order",tags={"order"})
public class OrderController {

    @Resource
    private OrderService orderService;

    @ApiOperation(value = "创建订单", nickname = "createOrder")
    @SPI(value = CreateOrderParam.class)
    @RequestMapping(path = "/spi/createOrder", method = RequestMethod.POST)
    public OrderDTO createOrder(@RequestBody @Valid CreateOrderParam param) {
        return orderService.createOrder(param);
    }

    @ApiOperation(value = "查询一行订单", nickname = "getOrder")
    @RequestMapping(path = "/getOrder", method = RequestMethod.GET)
    public BaseResult<OrderDTO> getOrder(@ApiIgnore @AuthenticationPrincipal UserInfoModel userInfoModel,
                                         @ModelAttribute GetOrderParam param)  {
        return orderService.getOrder(userInfoModel, param);
    }

    @ApiOperation(value = "查询订单列表", nickname = "listOrders")
    @RequestMapping(value = "/listOrders", method = RequestMethod.POST)
    public ListResult<OrderDTO> listOrders(@ApiIgnore @AuthenticationPrincipal UserInfoModel userInfoModel,
                                           @RequestBody ListOrdersParam param) {
        return orderService.listOrders(userInfoModel, param);
    }

    @ApiOperation(value = "订单退款", nickname = "refundOrder")
    @RequestMapping(value = "/refundOrder", method = RequestMethod.POST)
    public BaseResult<Long> refundOrder(@ApiIgnore @AuthenticationPrincipal UserInfoModel userInfoModel,
                                           @RequestBody RefundOrderParam param) {
        return orderService.refundOrders(userInfoModel, param);
    }
}
