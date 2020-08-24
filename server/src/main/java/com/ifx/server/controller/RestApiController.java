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

import com.ifx.server.entity.User;
import com.ifx.server.model.*;
import com.ifx.server.service.CoreService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import static org.springframework.web.bind.annotation.RequestMethod.GET;

@RestController
public class RestApiController {

    @Autowired
    private CoreService coreService;

    @GetMapping("/ping")
    @PostMapping("/ping")
    public Response<String> processPing() {
        return coreService.restPing();
    }

    @GetMapping("/get-username")
    public Response<String> processGetUsername() {
        return coreService.restGetUsername();
    }

    @PostMapping("/signup")
    public Response<String> processRegistration(@RequestBody User userForm, BindingResult bindingResult) {
        return coreService.restUserRegistration(userForm, bindingResult);
    }

    @PostMapping("/signin")
    public Response<String> processLogin(@RequestBody User userForm) {
        return coreService.restUserSignIn(userForm);
    }

    @GetMapping("/signout")
    public Response<String> setCookie(HttpServletRequest request) {
        return coreService.restUserSignOut(request);
    }

    @RequestMapping(value = "/error", method = GET, produces = MediaType.APPLICATION_JSON_VALUE)
    public Response<Integer> processError(HttpServletResponse response) {
        return coreService.restError(response);
    }

    @PostMapping("/attune")
    public Response<String> processAttune(@RequestBody Attune attune) {
        return coreService.restAttune(attune);
    }

    @PostMapping("/atelic-sample")
    public Response<AtelicResp> processAtelicSample(@RequestBody Atelic atelic) {
        return coreService.restAtelicSample(atelic);
    }

    @PostMapping("/atelic")
    public Response<AtelicResp> processAtelic(@RequestBody Atelic atelic) {
        return coreService.restAtelic(atelic);
    }

    @PostMapping("/attest")
    public Response<String> processAttest(@RequestBody Attest attest) {
        return coreService.restAttest(attest);
    }
}
