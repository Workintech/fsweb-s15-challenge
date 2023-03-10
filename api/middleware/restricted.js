const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../../config/index");

module.exports = async (req, res, next) => {
  /*
    EKLEYİN

    1- Authorization headerında geçerli token varsa, sıradakini çağırın.

    2- Authorization headerında token yoksa,
      response body şu mesajı içermelidir: "token gereklidir".

    3- Authorization headerında geçersiz veya timeout olmuş token varsa,
	  response body şu mesajı içermelidir: "token geçersizdir".
  */
  try {
    const token = req.headers.authorization; //tokenı aldık
    //token olmayabilir
    if (token) {
      //token var ve geçerli
      jwt.verify(token, JWT_SECRET, (err, decodedJWT) => {
        //verify 3 tane argüman alıyor token secret hata varsa err düşecek yoksa decodedJWT
        if (err) {
          //token var,geçersiz
          next({
            status: 401,
            message: "token geçersizdir",
          });
        } else {
          //token var geçerli
          req.decodedJWT = decodedJWT;
          next(); //kullanıcıyı bir sonraki middleware gönderiyoruz
        }
      });
    } else {
      next({ status: 401, message: "token gereklidir" });
    }
  } catch (error) {
    next(error);
  }
};
