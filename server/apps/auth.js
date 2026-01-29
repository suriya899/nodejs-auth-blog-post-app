import { Router } from "express";
import bcrypt from "bcrypt";

import { db } from "../utils/db.js"

import jwt from "jsonwebtoken"
const authRouter = Router();

// 🐨 Todo: Exercise #1
// ให้สร้าง API เพื่อเอาไว้ Register ตัว User แล้วเก็บข้อมูลไว้ใน Database ตามตารางที่ออกแบบไว้

authRouter.post("/register", async (req, res) => {
    try {
      // ดึงข้อมูลที่ client ส่งมาจาก req.body
      const { username, password, firstName, lastName } = req.body
  
      //ดึง collection users จาก database เพื่อใช้จัดการข้อมูลผู้ใช้
      const collection = db.collection("users")
      

      // ตรวจสอบว่า username มีในระบบ หรือยัง (กัน user ซ้ำ)
      const existedUser = await collection.findOne({ username })
      if (existedUser) {
        return res.status(400).json({
          message: "Username already exists",
        })
      }
  
      //สร้างค่า Salt (ค่ามั่ว) เพื่อใช้ hash password
      const salt = await bcrypt.genSalt(10)

      //นำ password ไป hash ด้วย bcrypt และ saltแล้วเก็บผลลัพธ์ใน hashedPassword
      const hashedPassword = await bcrypt.hash(password, salt)
  
      //สร้าง object user โดยเก็บ password เป็นค่าที่ถูก hash แล้ว (ไม่เก็บ password จริง)
      const user = {
        username,
        password: hashedPassword,
        firstName,
        lastName,
      }
      
      //บันทึกข้อมูล  user ลงใน database
      await collection.insertOne(user)
      
      //ถ้าสำเร็จ ส่งข้อความตอบกลับไปยัง client
      return res.json({
        message: "User has been created successfully",
      })

      //เกิด error จากฝั่ง server
    } catch (err) {
      console.error(err)
      return res.status(500).json({
        message: "Server error",
      })
    }
  })

// // 🐨 Todo: Exercise #3
// // ให้สร้าง API เพื่อเอาไว้ Login ตัว User ตามตารางที่ออกแบบไว้

  authRouter.post("/login", async (req, res) => {
    try {
        //ค้นหา user จาก collection user  
        // โดยใช้  username ที่ client ที่ส่งมาจาก req.body
      const user = await db.collection("users").findOne({
        username: req.body.username,
      })
      //ตรวจสอบข้อมูลว่าพบ user ในระบบหรือไม่ 
      // ถ้าไม่พบตอบกลับว่า  Invalid username or password
      if (!user) {
        return res.status(401).json({
          message: "Invalid username or password",
        })
      }
      //ใช้ bcrrypt.compare เปรียบเทียบรหัสผ่านที่ 
      // client ส่งมากับ รหัสที่ถูก hash ไว้ในฐานข้อมูล
      const isValidPassword = await bcrypt.compare(
        req.body.password,
        user.password
      )
      //ถ้าไม่ตรงกัน ให้คืนค่ากลับไปว่า "Invalid username or password"
      if (!isValidPassword) {
        return res.status(401).json({
          message: "Invalid username or password",
        })
      }
      
      //สร้าง JWT token โดยแนบข้อมูล user (id, firstName, lastName) ไว้ใน payload
      //กำหนดอายุ toke หมดอายุใน 15 นาที
      const token = jwt.sign(
        {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
        },
        process.env.SECRET_KEY,
        {
          expiresIn: "15m",
        }
      )

      //login สำเร็จ ส่ง token กลับไปให้ client
      return res.json({
        message: "login successfully",
        token,
      })
      
      //พบปัญหาฝั่ง server คืนค่า Server error
    } catch (err) {
      console.error(err)
      return res.status(500).json({
        message: "Server error",
      })
    }
  })
  

export default authRouter;
