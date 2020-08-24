/**
* MIT License
*
* Copyright (c) 2020 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*/

package com.ifx.server.controller;

import com.ifx.server.model.Message;
import com.ifx.server.model.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.messaging.simp.annotation.SendToUser;
import org.springframework.stereotype.Controller;
import java.security.Principal;

@Controller
public class WebSocketController {

    @Autowired
    private SimpMessagingTemplate simpMessagingTemplate;

    @MessageMapping("/public-test")
    @SendTo("/topic/public-test")
    public Response<String> sendPublic(Message message, Principal principal) throws Exception {
        // Send to private topic NOT using @SendToUser approach
        this.simpMessagingTemplate.convertAndSendToUser(principal.getName(), "/topic/private-test",
                new Response<String>(Response.STATUS_OK, "user: " + principal.getName() + "; stompClient.send(" + message.getText() + "); convertAndSendToUser(/topic/private-test)"));
        // Send to public topic using @SendTo approach
        return new Response<String>(Response.STATUS_OK, "user: " + principal.getName() + "; stompClient.send(" + message.getText() + "); @SendTo(/topic/public-test)");
    }

    @MessageMapping("/private-test")
    @SendToUser("/topic/private-test")
    public Response<String> sendPrivate(Message message, Principal principal) throws Exception {
        // Send to public topic NOT using @SendTo approach
        this.simpMessagingTemplate.convertAndSend("/topic/public-test",
                new Response<String>(Response.STATUS_OK, "user: " + principal.getName() + "; stompClient.send(" + message.getText() + "); convertAndSend(/topic/public-test)"));
        // Send to private topic using @SendToUser approach
        return new Response<String>(Response.STATUS_OK, "user: " + principal.getName() + "; stompClient.send(" + message.getText() + "); @SendToUser(/topic/private-test)");
    }
}
