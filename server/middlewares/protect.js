// 🐨 Todo: Exercise #5
// สร้าง Middleware ขึ้นมา 1 อันชื่อ Function ว่า `protect`
// เพื่อเอาไว้ตรวจสอบว่า Client แนบ Token มาใน Header ของ Request หรือไม่

//ตรวจสอบว่า token ถูกต้องหรือหมดอายุ
import jwt from 'jsonwebtoken'


export const protect = async (req, res, next)=>{
    //ตรวจสอบว่ามี token แนบมาใน header และมีรูปแบบถูกต้องหรือไม่
    const token = req.headers.authorization
    //ถ้าไม่ผ่าน ให้คืนข้อความ "Token has invalid format"
    if (!token || !token.startsWith('Bearer'))
        return res.status(401).json({
    message : "Token has invalid format"
})
    //token ถูกต้องเเละยังไม่หมดอายุ
    const tokenWithoutBearer = token.split(" ")[1];
    jwt.veryfy(tokenWithoutBearer,process.env.SECRET_KEY,
        (err,payload) =>{
            //ถ้า Token ไม่ผ่านเงื่อนไข ก็ให้ส่ง Response กลับไปว่า Token ที่ส่งเข้ามานั้น Invalid
            if (err){
                return res.status(401).json({
                    message: "Token is invalid"
                })
            }
           // นำข้อมูลผู้ใช้ที่แนบมากับ Token ใส่ลงไปใน Property user 
           // ของ Object req เพื่อที่จะนำไปใช้ต่อใน Controller Function ได้
           req.user = payload;
           next(); 
        }
    )

}
