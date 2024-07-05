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
package org.example.service.payment.impl;

import cn.hutool.http.ContentType;
import cn.hutool.json.JSONUtil;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.ijpay.core.kit.HttpKit;
import com.wechat.pay.contrib.apache.httpclient.auth.Verifier;
import com.wechat.pay.contrib.apache.httpclient.util.AesUtil;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.math3.util.Precision;
import org.example.common.BaseResult;
import org.example.common.adapter.BaseWechatPayClient;
import org.example.common.config.WechatPayConfig;
import org.example.common.constant.AliPayConstants;
import org.example.common.constant.PayChannel;
import org.example.common.constant.TradeStatus;
import org.example.common.constant.WechatPayConstants;
import org.example.common.dataobject.OrderDO;
import org.example.common.dto.OrderDTO;
import org.example.common.errorinfo.ErrorInfo;
import org.example.common.exception.BizException;
import org.example.common.helper.ots.OrderOtsHelper;
import org.example.common.model.UserInfoModel;
import org.example.common.param.order.GetOrderParam;
import org.example.common.utils.DateUtil;
import org.example.service.order.OrderService;
import org.example.service.payment.PaymentService;
import org.example.util.WechatPayValidatorUtil;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class WechatPayServiceImpl implements PaymentService {

    @Resource
    private WechatPayConfig wechatPayConfig;

    @Resource
    private OrderService orderService;

    @Resource
    private BaseWechatPayClient baseWechatPayClient;

    @Resource
    private OrderOtsHelper orderOtsHelper;

    private Verifier verifier;

    private final ReentrantLock lock = new ReentrantLock();

    private final String SUCCESS = "SUCCESS";

    @Override
    public void verifyTradeCallback(HttpServletRequest request, HttpServletResponse response) {
        Map<String, String> responseMap = new HashMap<>(12);
        Gson gson = new Gson();
        String body = HttpKit.readData(request);
        Type mapType = new TypeToken<Map<String, Object>>(){}.getType();
        Map<String, Object> bodyMap = gson.fromJson(body, mapType);
        try {
            String requestId = (String)bodyMap.get(WechatPayConstants.REQUEST_ID);
            verifier = baseWechatPayClient.getVerifier();
            WechatPayValidatorUtil wechatPayValidatorUtil
                    = new WechatPayValidatorUtil(verifier, requestId, body);
            if(!wechatPayValidatorUtil.validate(request)){
                log.error("支付通知验签失败");
                verifyFail(response, responseMap);
                return;
            }
            processOrder(bodyMap, responseMap, response);
            log.info("支付通知验签成功");
        } catch (Exception e) {
            throw new BizException(ErrorInfo.SIG_VERIFY_FAILED, e);
        }
    }

    @Override
    public void verifyRefundCallback(HttpServletRequest request, HttpServletResponse response) {
        Map<String, String> responseMap = new HashMap<>(12);
        Gson gson = new Gson();
        String body = HttpKit.readData(request);
        Type mapType = new TypeToken<Map<String, Object>>(){}.getType();
        Map<String, Object> bodyMap = gson.fromJson(body, mapType);
        try {
            String requestId = (String)bodyMap.get(WechatPayConstants.REQUEST_ID);
            verifier = baseWechatPayClient.getVerifier();
            WechatPayValidatorUtil wechatPayValidatorUtil
                    = new WechatPayValidatorUtil(verifier, requestId, body);
            if(!wechatPayValidatorUtil.validate(request)){
                log.error("退款通知验签失败");
                verifyFail(response, responseMap);
                return;
            }
            processRefund(bodyMap, responseMap, response);
            log.info("退款通知验签成功");
        } catch (Exception e) {
            throw new BizException(ErrorInfo.SIG_VERIFY_FAILED, e);
        }
    }

    @Override
    public String verifyTradeCallback(HttpServletRequest request) {
        throw new BizException(ErrorInfo.UNKNOWN_ERROR);
    }

    @Override
    public String verifyRefundCallback(HttpServletRequest request) {
        throw new BizException(ErrorInfo.UNKNOWN_ERROR);
    }

    @Override
    public String createOutTrade(OrderDTO order) {
        if (StringUtils.isNotEmpty(order.getPaymentForm()) && order.getPayChannel().equals(PayChannel.WECHATPAY)) {
            return order.getPaymentForm();
        }
        String transaction = baseWechatPayClient.nativePay(order);
        OrderDO orderDO = new OrderDO();
        orderDO.setOrderId(order.getOrderId());
        orderDO.setPayChannel(PayChannel.WECHATPAY);
        orderDO.setPaymentForm(transaction);
        orderOtsHelper.updateOrder(orderDO);
        return transaction;
    }

    @Override
    public Boolean refundOutTrade(OrderDTO order) {
        return baseWechatPayClient.refundOutTrade(order);
    }

    @Override
    public String getType() {
        return PayChannel.WECHATPAY.getValue();
    }

    public void processOrder(Map<String, Object> bodyMap, Map<String, String> responseMap, HttpServletResponse response)
            throws GeneralSecurityException {
        log.info("处理订单");

        String plainText = decryptFromResource(bodyMap);

        Gson gson = new Gson();
        Type mapType = new TypeToken<Map<String, Object>>(){}.getType();
        Map<String, Object> plainMap = gson.fromJson(plainText, mapType);
        String orderId = (String) plainMap.get(AliPayConstants.OUT_TRADE_NO);

        if(lock.tryLock()){
            try {
                OrderDTO orderFromOts = Optional.ofNullable(orderService.getOrder(null, new GetOrderParam(orderId)))
                        .map(BaseResult::getData)
                        .orElse(null);
                if (orderFromOts == null || orderFromOts.getTradeStatus() == null) {
                    verifyFail(response, responseMap);
                    return;
                }

                String tradeStatus = orderFromOts.getTradeStatus().name();
                if (Arrays.asList(TradeStatus.TRADE_SUCCESS.name(), TradeStatus.TRADE_FINISHED.name()).contains(tradeStatus)) {
                    verifySuccess(response);
                    return;
                }
                if (verifyBusinessData(plainMap, orderFromOts) && SUCCESS.equals(plainMap.get(WechatPayConstants.TRADE_STATE))) {
                    OrderDO verifiedOrder = new OrderDO();
                    String currentIs08601Time = DateUtil.getCurrentIs08601Time();
                    verifiedOrder.setGmtPayment(currentIs08601Time);
                    verifiedOrder.setOrderId(orderId);
                    verifiedOrder.setProductComponents(orderFromOts.getProductComponents());
                    verifiedOrder.setTradeStatus(TradeStatus.TRADE_SUCCESS);
                    verifiedOrder.setPayPeriod(orderFromOts.getPayPeriod());
                    verifiedOrder.setPayPeriodUnit(orderFromOts.getPayPeriodUnit());
                    verifiedOrder.setServiceId(orderFromOts.getServiceId());
                    if (StringUtils.isEmpty(verifiedOrder.getServiceInstanceId())) {
                        verifiedOrder.setServiceInstanceId(orderFromOts.getServiceInstanceId());
                    }
                    UserInfoModel userInfoModel = new UserInfoModel();
                    userInfoModel.setAid(String.valueOf(orderFromOts.getAccountId()));
                    orderService.updateOrder(userInfoModel, verifiedOrder);
                    verifySuccess(response);
                    return;
                }
                verifyFail(response, responseMap);
            } catch (IOException e) {
                throw new BizException(ErrorInfo.SIG_VERIFY_FAILED, e);
            } finally {
                lock.unlock();
            }
        }
    }

    public void processRefund(Map<String, Object> bodyMap, Map<String, String> responseMap, HttpServletResponse response)
            throws GeneralSecurityException {
        log.info("退款单");

        String plainText = decryptFromResource(bodyMap);
        Gson gson = new Gson();
        Type mapType = new TypeToken<Map<String, Object>>(){}.getType();
        Map<String, Object> plainMap = gson.fromJson(plainText, mapType);
        String orderId = (String) plainMap.get(AliPayConstants.OUT_TRADE_NO);

        if(lock.tryLock()){
            try {
                OrderDTO orderFromOts = Optional.ofNullable(orderService.getOrder(null,
                                new GetOrderParam(orderId)))
                        .map(BaseResult::getData)
                        .orElse(null);

                if (orderFromOts == null || orderFromOts.getTradeStatus() == null) {
                    verifyFail(response, responseMap);
                    return;
                }
                String tradeStatus = orderFromOts.getTradeStatus().name();
                if (TradeStatus.REFUNDED.name().equals(tradeStatus)) {
                    verifySuccess(response);
                    return;
                }
                if (verifyRefundData(plainMap, orderFromOts) &&
                        SUCCESS.equals(plainMap.get(WechatPayConstants.REFUND_STATE))) {
                    OrderDO verifiedOrder = new OrderDO();
                    String currentIs08601Time = DateUtil.getCurrentIs08601Time();
                    verifiedOrder.setRefundDate(currentIs08601Time);
                    verifiedOrder.setOrderId(orderId);
                    verifiedOrder.setProductComponents(orderFromOts.getProductComponents());
                    verifiedOrder.setTradeStatus(TradeStatus.REFUNDED);
                    verifiedOrder.setPayPeriod(orderFromOts.getPayPeriod());
                    verifiedOrder.setPayPeriodUnit(orderFromOts.getPayPeriodUnit());
                    verifiedOrder.setServiceId(orderFromOts.getServiceId());
                    if (StringUtils.isEmpty(verifiedOrder.getServiceInstanceId())) {
                        verifiedOrder.setServiceInstanceId(orderFromOts.getServiceInstanceId());
                    }
                    UserInfoModel userInfoModel = new UserInfoModel();
                    userInfoModel.setAid(String.valueOf(orderFromOts.getAccountId()));
                    orderService.updateOrder(userInfoModel, verifiedOrder);
                    verifySuccess(response);
                    return;
                }
                verifyFail(response, responseMap);
            } catch (IOException e) {
                throw new BizException(ErrorInfo.SIG_VERIFY_FAILED, e);
            } finally {
                lock.unlock();
            }
        }
    }

    private Boolean verifyBusinessData(Map<String, Object> unverifiedOrder, OrderDTO orderFromTableStore) {
        if (orderFromTableStore.getTotalAmount() == null) {
            return Boolean.FALSE;
        }
        Object amountObj = unverifiedOrder.get(WechatPayConstants.AMOUNT);
        Map<?, ?> amountMap = (Map<?, ?>) amountObj;
        Double totalAmountDouble = (Double) amountMap.get(WechatPayConstants.TOTAL_AMOUNT);
        int totalAmount = totalAmountDouble.intValue();
        return unverifiedOrder.get(WechatPayConstants.MCH_ID).equals(wechatPayConfig.getMchId())
                && unverifiedOrder.get(WechatPayConstants.APP_ID).equals(wechatPayConfig.getAppId())
                && Precision.equals(orderFromTableStore.getTotalAmount().intValue(), totalAmount);
    }

    private Boolean verifyRefundData(Map<String, Object> unverifiedOrder, OrderDTO orderFromTableStore) {
        if (orderFromTableStore.getTotalAmount() == null) {
            return Boolean.FALSE;
        }
        Object amountObj = unverifiedOrder.get(WechatPayConstants.AMOUNT);
        Map<?, ?> amountMap = (Map<?, ?>) amountObj;
        Double totalAmountDouble = (Double) amountMap.get(WechatPayConstants.TOTAL_AMOUNT);
        int totalAmount = totalAmountDouble.intValue();
        Double refundAmountDouble = (Double) amountMap.get(WechatPayConstants.REFUND_AMOUNT);
        int refundAmount = refundAmountDouble.intValue();
        return unverifiedOrder.get(WechatPayConstants.MCH_ID).equals(wechatPayConfig.getMchId())
                && Precision.equals(orderFromTableStore.getTotalAmount().intValue(), totalAmount)
                && Precision.equals(orderFromTableStore.getRefundAmount().intValue(), refundAmount);
    }

    private void verifySuccess(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader("Content-type", ContentType.JSON.toString());
        response.flushBuffer();
    }

    private void verifyFail(HttpServletResponse response, Map<String, String> responseMap) throws IOException {
        response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        responseMap.put("code", "ERROR");
        responseMap.put("message", "签名错误");
        response.setHeader("Content-type", ContentType.JSON.toString());
        response.getOutputStream().write(JSONUtil.toJsonStr(responseMap).getBytes(StandardCharsets.UTF_8));
        response.flushBuffer();
    }

    private String decryptFromResource(Map<String, Object> bodyMap) throws GeneralSecurityException {
        log.info("密文解密");

        Map<String, String> resourceMap = (Map) bodyMap.get("resource");
        String ciphertext = resourceMap.get("ciphertext");
        String nonce = resourceMap.get("nonce");
        String associatedData = resourceMap.get("associated_data");

        AesUtil aesUtil = new AesUtil(wechatPayConfig.getApiV3Key().getBytes(StandardCharsets.UTF_8));
        return aesUtil.decryptToString(associatedData.getBytes(StandardCharsets.UTF_8),
                nonce.getBytes(StandardCharsets.UTF_8),
                ciphertext);
    }
}