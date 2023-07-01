import request from "supertest";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import app from "../src/server";

describe("Login System API Tests", () => {
  let token: string;

  beforeAll(async () => {
    // Initialize the users array
    app.locals.users = [];

    // Register a test user
    const password = await bcrypt.hash("password", 10);
    const testUser = { username: "testuser", password: "password" };
    await request(app)
      .post("/register")
      .send({ username: "testuser", password: "password" });

    // Generate a JWT token for the test user
    token = jwt.sign({ username: testUser.username }, "your-secret-key");
  });

  it("should register a new user", async () => {
    const response = await request(app)
      .post("/register")
      .send({ username: "newuser", password: "newpassword" });

    expect(response.status).toBe(201);
    expect(response.body.message).toBe("User registered successfully");
  });

  it("should return an error when registering with missing username", async () => {
    const response = await request(app)
      .post("/register")
      .send({ password: "newpassword" });

    expect(response.status).toBe(400);
    expect(response.body.message).toBe("Username and password are required");
  });

  it("should return an error when registering with missing password", async () => {
    const response = await request(app)
      .post("/register")
      .send({ username: "newuser" });

    expect(response.status).toBe(400);
    expect(response.body.message).toBe("Username and password are required");
  });

  it("should return an error when registering with an existing username", async () => {
    const response = await request(app)
      .post("/register")
      .send({ username: "testuser", password: "newpassword" });

    expect(response.status).toBe(400);
    expect(response.body.message).toBe("Username already exists");
  });

  it("should log in a user", async () => {
    const response = await request(app)
      .post("/login")
      .send({ username: "testuser", password: "password" });

    expect(response.status).toBe(200);
    expect(response.body.message).toBe("Login successful");
    expect(response.body.token).toBeDefined();
  });

  it("should return an error when logging in with missing username", async () => {
    const response = await request(app)
      .post("/login")
      .send({ password: "password" });

    expect(response.status).toBe(400);
    expect(response.body.message).toBe("Username and password are required");
  });

  it("should return an error when logging in with missing password", async () => {
    const response = await request(app)
      .post("/login")
      .send({ username: "testuser" });

    expect(response.status).toBe(400);
    expect(response.body.message).toBe("Username and password are required");
  });

  it("should return an error when logging in with an invalid username", async () => {
    const response = await request(app)
      .post("/login")
      .send({ username: "invaliduser", password: "password" });

    expect(response.status).toBe(401);
    expect(response.body.message).toBe("User not found");
  });

  it("should access protected route with a valid token", async () => {
    const response = await request(app)
      .get("/protected")
      .set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(200);
    expect(response.body.message).toBe("Protected data");
  });

  it("should return an error when accessing protected route without a token", async () => {
    const response = await request(app).get("/protected");

    expect(response.status).toBe(401);
    expect(response.body.message).toBe("Missing authorization token");
  });

  it("should return an error when accessing protected route with an Invalid authorization token", async () => {
    const response = await request(app)
      .get("/protected")
      .set("Authorization", "Bearer invalidtoken");

    expect(response.status).toBe(401);
    expect(response.body.message).toBe("Invalid authorization token");
  });
});
