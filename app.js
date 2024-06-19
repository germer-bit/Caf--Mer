const express = require("express") 
const mysql = require("mysql") 
const bcrypt = require("bcrypt") 
const session = require("express-session") 
const path = require("path") 
const bodyParser = require("body-parser") 

const app = express() 
const PORT = process.env.PORT || 3000 

// Configurar conexión a MySQL
const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "login",
}) 

// Conectar a MySQL
connection.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL:", err) 
    return 
  }
  console.log("Connected to MySQL") 
}) 

// Middleware para manejar JSON y datos de formulario en las solicitudes
app.use(express.json()) 
app.use(bodyParser.json()) 
app.use(bodyParser.urlencoded({ extended: false })) 

// Configurar sesiones
app.use(
  session({
    secret: "secret", // Secreto para firmar las cookies de sesión
    resave: true,
    saveUninitialized: true,
  })
) 

// Middleware para verificar sesión de usuario
function requireLogin(req, res, next) {
  if (req.session.loggedin) {
    next()  // El usuario está autenticado, permitir acceso
  } else {
    res.redirect("/index.html")  // Redirigir al inicio si no está autenticado
  }
}

// Servir archivos estáticos
app.use("/assets/styles", express.static(path.join(__dirname, "assets/styles"))) 
app.use("/assets/imges", express.static(path.join(__dirname, "assets/imges"))) 
app.use(express.static(path.join(__dirname, "public"))) 
app.use(express.static(path.join(__dirname, "page"))) 

// Endpoint para la página de bienvenida protegida por autenticación
app.get("/welcome.html", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "/page/welcome.html")) 
}) 

// Endpoint para cerrar sesión
app.get("/logout", (req, res) => {
  req.session.destroy()  // Destruir sesión al hacer logout
  res.redirect("/index.html")  // Redirigir al inicio después de logout
}) 

// Endpoint para registrar nuevos usuarios
app.post("/register", (req, res) => {
  const { username, password } = req.body 

  // Verificar si el username ya existe en la base de datos
  connection.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    (err, results) => {
      if (err) {
        return res.status(500).send("Error al verificar usuario") 
      }

      if (results.length > 0) {
        return res.status(400).send("El nombre de usuario ya está en uso") 
      }

      // Si el username no existe, proceder con el registro
      bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
          return res.status(500).send("Error al registrar") 
        }

        const user = { username, password: hash } 
        connection.query("INSERT INTO users SET ?", user, (err, results) => {
          if (err) {
            return res.status(500).send("Error al registrar") 
          }
          res.redirect("/register-success") 
        }) 
      }) 
    }
  ) 
}) 

// Endpoint para manejar el éxito del registro
app.get("/register-success", (req, res) => {
  res.send(`
    <script>
      alert('Usuario registrado con éxito') 
      window.location.href = '/index.html' 
    </script>
  `) 
}) 

// Endpoint para autenticar usuarios
app.post("/authenticate", (req, res) => {
  const { username, password } = req.body;

  // Buscar usuario en la base de datos por username
  connection.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    (err, results) => {
      if (err) {
        return res.status(500).send("Error al acceder");
      }
      if (results.length === 0) {
        // Redirigir a página de error si usuario no existe
        return res.redirect("/auth-error.html");
      }

      const user = results[0];
      // Comparar contraseña ingresada con la almacenada en la base de datos
      bcrypt.compare(password, user.password, (err, result) => {
        if (err) {
          return res.status(500).send("Error al autenticar");
        }
        if (result) {
          req.session.loggedin = true; // Establecer sesión de usuario
          req.session.username = username;
          res.redirect("/welcome.html"); // Redirigir a la página de bienvenida si autenticación es exitosa
        } else {
          // Redirigir a página de error si contraseña es incorrecta
          res.redirect("/auth-error.html");
        }
      });
    }
  );
});

// Iniciar el servidor
app.listen(PORT, () => {
  console.log("--------------------------------------------") 
  console.log(`Servidor iniciado en http://localhost:${PORT}`) 
  console.log("--------------------------------------------") 
}) 
