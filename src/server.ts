import express, { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt, { JwtPayload } from "jsonwebtoken";

const app = express();
app.use(express.json());

// In-memory user database (replace with a database in production)
const users: { username: string; password: string }[] = [];

app.post("/register", async (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }

  const existingUser = users.find((user) => user.username === username);
  if (existingUser) {
    return res.status(400).json({ message: "Username already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  users.push({ username, password: hashedPassword });

  res.status(201).json({ message: "User registered successfully" });
});

app.post("/login", async (req: Request, res: Response) => {
  const { username, password } = req.body;
  console.log(username, password);
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }

  const user = users.find((user) => user.username === username);
  if (!user) {
    return res.status(401).json({ message: "User not found" });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ message: "Invalid password" });
  }

  const token = jwt.sign({ username }, "your-secret-key");

  res.json({ message: "Login successful", token });
});

app.get("/protected", (req: Request, res: Response) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Missing authorization token" });
  }

  try {
    const decodedToken = jwt.verify(token, "your-secret-key") as JwtPayload;
    if (!decodedToken.username) {
      throw new Error();
    }
    res.json({ message: "Protected data", username: decodedToken.username });
  } catch (error) {
    return res.status(401).json({ message: "Invalid authorization token" });
  }
});

const port = 3000;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

export default app;
