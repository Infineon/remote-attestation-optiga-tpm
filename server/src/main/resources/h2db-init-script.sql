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

INSERT INTO role (name) VALUES
  ('ROLE_ADMIN'),
  ('ROLE_GUEST'),
  ('ROLE_USER');

INSERT INTO user (username, password) VALUES
  ('admin', '$2a$10$FHsa61eu6/OwjX3WyKP.0.y7b8wS2PW/.jrOcflgFqflq.5SVXDZ6'), /* password: password */
  ('infineon', '$2a$10$FHsa61eu6/OwjX3WyKP.0.y7b8wS2PW/.jrOcflgFqflq.5SVXDZ6'); /* password: password */

INSERT INTO user_roles (users_id, roles_id) VALUES
  ('1', '1'),
  ('1', '2'),
  ('1', '3'),
  ('2', '3');

