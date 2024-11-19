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

package com.ifx.server.entity;

import com.fasterxml.jackson.annotation.*;
import lombok.Getter;
import lombok.Setter;
import javax.persistence.*;
import java.util.Set;

@Entity
@Table(name = "role") // automate creation of table 'role'
@Getter
@Setter
public class Role {

    @Transient
    public static final String ROLE_ADMIN = "ROLE_ADMIN";
    @Transient
    public static final String ROLE_USER = "ROLE_USER";
    @Transient
    public static final String ROLE_GUEST = "ROLE_GUEST";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Getter(onMethod_=@JsonIgnore) // ignore this field during Jackson serialization
    private Long id;

    private String name;

    @Getter(onMethod_=@JsonIgnore) // ignore this field to prevent infinite recursive during Jackson serialization of User.class
    @ManyToMany(mappedBy = "roles")
    private Set<User> users;
}
