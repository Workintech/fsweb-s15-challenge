// testleri buraya yazın
const superTest = require("supertest");
const server = require("./server");
const db = require("../data/dbConfig");
const bcrypt = require("bcryptjs");

beforeAll(async () => {
  await db.migrate.rollback();
  await db.migrate.latest();
});

beforeAll(async () => {
  await db.seed.run();
});

// testleri buraya yazın
test("[0] Testler çalışır durumda]", () => {
  expect(true).toBe(true);
});

describe("Server Test", () => {
  it("[1] Server çalışıyor mu", async () => {
    const res = await superTest(server).get("/");
    expect(res.status).toBe(200);
    expect(res.body.message).toBe("Server Çalışıyor");
  });
});

describe("Auth Test", () => {
  it("[2] Register Başarılı mı", async () => {
    const res = await superTest(server)
      .post("/api/auth/register")
      .send({ username: "bob2", password: "1234" });
    expect(res.status).toBe(201);
    const isHashed = bcrypt.compareSync("1234", res.body.password);
    expect(isHashed).toBeTruthy();
  }, 1000);
  it("[3] username boş olunca doğru hata dönüyor mu", async () => {
    const res = await superTest(server)
      .post("/api/auth/register")
      .send({ password: "1234" });
    expect(res.status).toBe(400);
    console.log(res.body);
    expect(res.body.message).toBe("username ve şifre gereklidir");
  }, 1000);
  it("[4] username aynı olunca hata dönüyor mu", async () => {
    const res = await superTest(server)
      .post("/api/auth/register")
      .send({ username: "bob", password: "1234" });
    expect(res.status).toBe(401);
    expect(res.body.message).toBe("username alınmış");
  }, 1000);
  it("[5] login oluyor mu", async () => {
    const res = await superTest(server)
      .post("/api/auth/login")
      .send({ username: "bob", password: "1234" });
    expect(res.status).toBe(200);
    expect(res.body.message).toBe("welcome, bob");
    expect(res.body.token).toBeDefined();
  }, 1000);
});
