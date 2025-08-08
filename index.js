const express = require("express");
const { Sequelize, Model, DataTypes, json } = require("sequelize");
let cors = require("cors");
const https = require("https");
const http = require("http");
const fs = require("fs");
const app = express();
const axios = require("axios");
const csrf = require("csurf");
const cookieParser = require("cookie-parser");
const config = require("./config/config");
//const configdos = require("./config/configdos");
require("dotenv").config();
const path = require("path");
const PORT = process.env.PORT || 5000;

const bodyParser = require("body-parser");
const validaTokenAuth = require("./middlewares/auth");

const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { jwtSecret } = require("./config/env");
//const { parse } = require("libphonenumber-js");

const agent = new https.Agent({
  rejectUnauthorized: false, // ⚠ Ignora errores de certificado (solo para desarrollo)
});

app.use(cors());
app.use(bodyParser.json());

app.use(cookieParser());

const rutaPrincipal = "/api/v1";

app.use(`${rutaPrincipal}`, (req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  res.header("Access-Control-Allow-Credentials", true);
  next();
});

app.use(express.json());

const csrfProtection = csrf({ cookie: true });
app.get(`${rutaPrincipal}/csrf-token`, csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

const sequelizeA = new Sequelize(
  config.development.database,
  config.development.username,
  config.development.password,
  {
    host: config.development.host,
    port: config.development.port,
    dialect: config.development.dialect,
    logging: console.log,
  }
);

//sequelizeA.sync();
class User extends Model {}
User.init(
  {
    username: DataTypes.STRING,
    database: DataTypes.STRING,
    email: DataTypes.STRING,
    password: DataTypes.TEXT,
    licenciaactiva: DataTypes.INTEGER,
    status: DataTypes.INTEGER,
    //created_at: DataTypes.TEXT,
  },
  {
    sequelize: sequelizeA,
    modelName: "users",
    timestamps: false,
    createdAt: false,
    updatedAt: false,
  }
);
class Vendedor extends Model {}
Vendedor.init(
  {
    admin: DataTypes.STRING,
    username: DataTypes.STRING,
    nombre: DataTypes.STRING,
    apellido: DataTypes.STRING,
    celular: DataTypes.STRING,
    email: DataTypes.STRING,
    password: DataTypes.TEXT,
    permiso: DataTypes.INTEGER,
    permisocrud: DataTypes.TEXT,
    //created_at: DataTypes.TEXT,
  },
  {
    sequelize: sequelizeA,
    modelName: "vendedores",
    timestamps: false,
    createdAt: false,
    updatedAt: false,
  }
);

app.post(`${rutaPrincipal}/auth/login`, async (req, res) => {
  const csrf_token = req.header("X-CSRF-Token");
  // Verificar si no hay token
  if (!csrf_token) {
    return res
      .status(401)
      .json({ message: "No hay token csrf, autorización denegada" });
  }

  try {
    const { username, password } = req.body;

    const vendedor = await Vendedor.findOne({ where: { username: username } });
    if (vendedor !== null) {
      // Verificar contraseña
      const isMatch = await bcrypt.compare(password, vendedor.password);
      if (!isMatch) {
        return res.status(401).json({ message: "Contraseña inválida" });
      }

      // Crear y firmar JWT
      const token = jwt.sign(
        { id: vendedor.id, username: vendedor.admin },
        jwtSecret,
        {
          expiresIn: "12h", // 1m 10m 30m 1h 3h 6h 12h 24h 1d
        }
      );

      return res.json({
        token,
        user: {
          id: vendedor.id,
          username: vendedor.admin,
          vendedor: vendedor.username,
          email: vendedor.email,
        },
        permiso: vendedor.permiso,
      });
    }

    const user = await User.findOne({ where: { username: username } });
    if (user === null) {
      return res.status(401).json({ message: "Cedula inválida" });
    }

    // Verificar contraseña
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Contraseña inválida" });
    }

    // Crear y firmar JWT
    const token = jwt.sign(
      { id: user.id, username: user.username },
      jwtSecret,
      {
        expiresIn: "12h", // 1m 10m 30m 1h 3h 6h 12h 24h 1d
      }
    );

    const permiso = user.licenciaactiva;
    const status = user.status;

    return res.json({
      token,
      user: { id: user.id, username: user.database, email: user.email },
      permiso: permiso,
      status: status,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post(`${rutaPrincipal}/auth/register`, async (req, res) => {
  const csrf_token = req.header("X-CSRF-Token");
  // Verificar si no hay token
  if (!csrf_token) {
    return res
      .status(401)
      .json({ message: "No hay token csrf, autorización denegada" });
  }

  try {
    const { username, database, email, password } = req.body;

    const user = await User.findOne({ where: { username: username } });
    if (user) {
      return res
        .status(401)
        .json({ message: "Cedula inválida ya está en uso" });
    }

    const correo = await User.findOne({ where: { email: email } });
    if (correo) {
      return res
        .status(401)
        .json({ message: "Correo inválido ya está en uso" });
    }

    bcrypt.hash(password, 10, (err, hash) => {
      if (err) return callback(err);

      const registro = {
        username: username,
        database: database,
        email: email,
        password: hash,
      };

      User.create(registro);
    });
    res.status(201).json({ message: "Usuario registrado exitosamente" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get(
  `${rutaPrincipal}/:connectionName/vendedor`,
  validaTokenAuth,
  validateConnection,
  async (req, res) => {
    try {
      const { connectionName } = req.params;
      const vendedores = await Vendedor.findAll({
        where: { admin: connectionName.slice(0, -2) },
      });
      res.status(201).json(vendedores);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }
);

app.post(
  `${rutaPrincipal}/:connectionName/vendedor`,
  validaTokenAuth,
  validateConnection,
  async (req, res) => {
    try {
      const { connectionName } = req.params;
      const { username, nombre, apellido, celular, email, password, permiso } =
        req.body;

      const user = await Vendedor.findOne({ where: { username: username } });
      if (user) {
        return res
          .status(401)
          .json({ message: "Cedula inválida ya está en uso" });
      }

      const correo = await Vendedor.findOne({ where: { email: email } });
      if (correo) {
        return res
          .status(401)
          .json({ message: "Correo inválido ya está en uso" });
      }

      //console.log("CONTRESEÑA DEL VENDEDOR: ", password);
      bcrypt.hash(password, 10, (err, hash) => {
        if (err) return callback(err);

        const registro = {
          admin: connectionName.slice(0, -2),
          username: username,
          nombre: nombre,
          apellido: apellido,
          celular: celular,
          email: email,
          password: hash,
          permiso: permiso,
        };

        Vendedor.create(registro);
      });
      res.status(201).json({ message: "Vendedor registrado exitosamente" });
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }
);

app.put(
  `${rutaPrincipal}/:connectionName/vendedorcrud/:id`,
  validaTokenAuth,
  validateConnection,
  async (req, res) => {
    try {
      const { id } = req.params;
      const [updated] = await Vendedor.update(req.body, {
        where: { id },
      });
      if (updated) {
        const updatedRecord = await Vendedor.findByPk(id);
        res.json(updatedRecord);
      } else {
        res.status(404).json({ error: "Registro no encontrado" });
      }
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }
);

// Almacén de conexiones y modelos
let dbRegistry = {};

// Middleware para verificar conexión
function validateConnection(req, res, next) {
  const { connectionName } = req.params;
  if (!dbRegistry[connectionName]) {
    return res
      .status(404)
      .json({ error: `Conexión '${connectionName}' no encontrada` });
  }
  req.db = dbRegistry[connectionName];
  next();
}

// 1. Ruta para crear conexión
app.post(`${rutaPrincipal}/connections`, validaTokenAuth, async (req, res) => {
  const { connectionName, dbPath } = req.body;

  /*
  connectionName  => VARIABLE DE SESION
  dbPath => NOMBRE DE LA BASE DE DATOS
  */

  if (!connectionName || !dbPath) {
    return res
      .status(400)
      .json({ error: "Se requieren connectionName y dbPath" });
  }

  if (dbRegistry[connectionName]) {
    return (
      res
        //.status(400)
        .json({ error: "El nombre de conexión ya está en uso" })
    );
  }

  try {
    const sequelize = new Sequelize(
      `dblx_${dbPath}`,
      config.development.username,
      config.development.password,
      {
        host: config.development.host,
        port: config.development.port,
        dialect: config.development.dialect,
        define: {
          timestamps: false,
          createdAt: false,
          updatedAt: false,
        },
        logging: console.log,
      }
    );

    await sequelize.authenticate();

    // Estructura para almacenar la conexión y modelos
    dbRegistry[connectionName] = {
      sequelize,
      models: {},
    };

    //console.log(dbRegistry[connectionName]);

    res.json({
      success: true,
      message: `Conexión '${connectionName}' establecida con ${dbPath}`,
    });
  } catch (error) {
    res.status(500).json({
      error: "Error al conectar a la base de datos",
      details: error.message,
    });
  }
});

// 1.1. Ruta para cerrar conexión
app.post(
  `${rutaPrincipal}/connectionsclose`,
  validaTokenAuth,
  async (req, res) => {
    const { connectionName, dbPath } = req.body;
    try {
      const newDbRegistry = {};

      Object.entries(dbRegistry).forEach(([key, value]) => {
        if (key !== connectionName) {
          //console.log(key)
          //console.log(value)
          newDbRegistry[key] = value;
        }
      });
      dbRegistry = newDbRegistry;
      console.log(dbRegistry);

      res.json({
        success: true,
        message: `Conexión '${connectionName}' cerrada con ${dbPath}`,
      });
    } catch (error) {
      res.status(500).json({
        error: "Error al desconectar a la base de datos",
        details: error.message,
      });
    }
  }
);

// 2. Ruta para definir un modelo
app.post(
  `${rutaPrincipal}/:connectionName/models`,
  validaTokenAuth,
  validateConnection,
  async (req, res) => {
    const { connectionName } = req.params;
    const { modelName, attributes } = req.body;

    if (!modelName || !attributes) {
      return res
        .status(400)
        .json({ error: "Se requieren modelName y attributes" });
    }

    let newAttrib = {};
    //const fechaActual = new Date();
    //const fechaFormateada = fechaActual.toISOString().slice(0, 19).replace('T', ' ');
    Object.entries(attributes).forEach(([key, value]) => {
      if (value === "STRING") {
        newAttrib[key] = { type: DataTypes.STRING(100) };
      } else if (value === "REAL") {
        newAttrib[key] = { type: DataTypes.DOUBLE(10, 2) };
      } else if (value === "INTEGER") {
        if (key === "status" || key === "exento") {
          newAttrib[key] = { type: DataTypes.INTEGER, defaultValue: 0 };
        } else {
          newAttrib[key] = { type: DataTypes.INTEGER };
        }
      } else if (value === "TEXT") {
        newAttrib[key] = { type: DataTypes.TEXT };
      }
    });

    try {
      const model = req.db.sequelize.define(modelName, newAttrib);
      //await model.drop();
      await model.sync();
      req.db.models[modelName] = model;

      if (modelName === "configs") {
        const configuracion = await model.findByPk(1);
        if (configuracion === null) {
          await model.create({
            viewMode: "list",
          });
        }
      }

      res.json({
        success: true,
        message: `Modelo '${modelName}' creado en '${connectionName}'`,
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// 3. Rutas CRUD para cada modelo

// CREATE (POST)
app.post(
  `${rutaPrincipal}/:connectionName/:modelName`,
  validaTokenAuth,
  validateConnection,
  async (req, res) => {
    const { modelName } = req.params;
    const model = req.db.models[modelName];

    if (!model) {
      return res
        .status(404)
        .json({ error: `Modelo '${modelName}' no encontrado` });
    }

    try {
      if (modelName === "ventas") {
        const venta = {
          clienteid: req.body.clienteid,
          codventa: req.body.codventa,
          fecha: req.body.fecha,
          subtotal: req.body.subtotal,
          iva: req.body.iva,
          total: req.body.total,
          status: 1,
        };
        const records = await model.create(venta);
        //console.log(records.dataValues.id)
        const modelvd = req.db.models["ventasdetalles"];
        req.body.productos.forEach((element) => {
          const detalle = {
            ventaid: records.dataValues.id,
            productoid: element.productoid,
            cantidad: element.cantidad,
            preciounitario: element.preciounitario,
          };
          modelvd.create(detalle);
        });
        return res.json(records);
      }
      if (modelName === "pedidos") {
        req.body.productosid.forEach((element) => {
          const pedido = {
            clienteid: req.body.clienteid,
            nombre: req.body.nombre,
            productosid: element.productoid,
            fecha: req.body.fecha,
            cantidad: element.cantidad,
            preciounitario: element.preciounitario,
            stock: element.stock,
          };
          //console.log(pedido)
          model.create(pedido);
        });
        return res.json({ info: "pedidos creado" });
      }
      if (modelName === "compras") {
        req.body.forEach((element) => {
          const compras = {
            proveedorid: element.proveedorid,
            fecha: element.fecha,
            productoid: element.productoid,
            cantidad: element.cantidad,
            cantunidades: element.cantunidades,
            mayordetal: element.mayordetal,
            preciounitario: element.preciounitario,
            subtotal: element.subtotal,
            iva: element.iva,
            total: element.total,
            status: 1,
          };
          model.create(compras);
          const modelp = req.db.models["productos"];
          updateCostosPreciosProductos(
            element.preciounitario,
            element.tasa,
            element.porcentaje,
            element.costo,
            element.productoid,
            modelp
          );
        });
        return res.json({ info: "compra creada" });
      }
      const record = await model.create(req.body);
      res.status(201).json(record);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// READ ALL (GET)
app.get(
  `${rutaPrincipal}/:connectionName/:modelName`,
  validaTokenAuth,
  validateConnection,
  async (req, res) => {
    const { modelName } = req.params;
    const model = req.db.models[modelName];

    if (!model) {
      return res
        .status(404)
        .json({ error: `Modelo '${modelName}' no encontrado` });
    }

    try {
      if (modelName === "productos") {
        const records = await dataProductosModulo(req.db.sequelize);
        return res.json(records);
      }
      if (modelName === "ventas") {
        const [recordsVentas, recordsven] = await req.db.sequelize.query(`
        SELECT 
          t1.id,
          (SELECT nombre FROM clientes WHERE id = t1.clienteid) AS nombre,
          (SELECT apellido FROM clientes WHERE id = t1.clienteid) AS apellido, 
          t1.fecha, 
          t1.subtotal, 
          t1.iva, 
          t1.total, 
          t1.status
          FROM ventas AS t1
        ORDER BY t1.id DESC;
        `);
        const [recordsCompras, recordscom] = await req.db.sequelize.query(`
        SELECT t1.productoid, t1.cantidad, t1.cantunidades, t1.mayordetal FROM compras t1;
        `);
        /*
        SELECT
            t1.id,
            t1.codigop,
            t1.nombre,
            (SELECT nombre FROM categorias WHERE id = t1.categoriaid) AS categorias,
            t1.precioventa,
            COALESCE(t1.stock + SUM(t2.cantidad), t1.stock) - COALESCE((SELECT SUM(cantidad) FROM ventasdetalles WHERE productoid = t1.id ), 0) - COALESCE((SELECT SUM(cantidad) FROM pedidos WHERE productosid = t1.id), 0) AS stock,
            t1.imagen,
            (t1.precioventa / t1.tasa) AS costo,
            t1.detalmayor,
            t1.status,
            t1.exento
          FROM
            productos t1
          LEFT JOIN
            compras t2 ON t1.id = t2.productoid
          GROUP BY t1.id;
        */
        const [recordsProductos, recordspro] = await req.db.sequelize.query(`
          SELECT
            t1.id,
            t1.codigop,
            t1.nombre,
            (SELECT nombre FROM categorias WHERE id = t1.categoriaid) AS categorias,
            t1.precioventa,
            COALESCE(t1.stock + ( COALESCE((SELECT SUM(cantidad) FROM compras WHERE productoid = t1.id),0) ), t1.stock) - COALESCE((SELECT SUM(cantidad) FROM ventasdetalles WHERE productoid = t1.id ), 0) - COALESCE((SELECT SUM(cantidad) FROM pedidos WHERE productosid = t1.id), 0) AS stock,
            t1.imagen,
            (t1.precioventa / t1.tasa) AS costo,
            t1.detalmayor,
            t1.status,
            t1.exento
          FROM
            productos t1
          GROUP BY t1.id;
          `);
        return res.json({
          ventas: recordsVentas,
          productos: recordsProductos,
          compras: recordsCompras,
        });
      }
      if (modelName === "compras") {
        const [records, recordsc] = await req.db.sequelize.query(`
        SELECT 
        t1.id,
        (SELECT nombre FROM proveedores WHERE id = t1.proveedorid) AS empresa,
        (SELECT nombre FROM productos WHERE id = t1.productoid) AS producto,
        t1.fecha, t1.cantidad, 
        t1.preciounitario, 
        t1.subtotal, 
        t1.iva, 
        t1.total, 
        t1.status
        FROM compras t1
        ORDER BY t1.id DESC;
        `);
        return res.json(records);
      }
      if (modelName === "inventarios") {
        const records = await Inventario(req.db.sequelize);
        return res.json(records);
      }
      const records = await model.findAll();
      res.json(records);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// READ ONE (GET)
app.get(
  `${rutaPrincipal}/:connectionName/:modelName/:id`,
  validaTokenAuth,
  validateConnection,
  async (req, res) => {
    const { modelName, id } = req.params;
    const model = req.db.models[modelName];

    if (!model) {
      return res
        .status(404)
        .json({ error: `Modelo '${modelName}' no encontrado` });
    }

    try {
      if (modelName === "ventas" && id === "ultimafactura") {
        const records = await model.max("id");
        return res.json(records);
      }
      if (modelName === "pedidos") {
        const records = await model.findAll({
          where: {
            clienteid: id,
          },
        });
        return res.json(records);
      }
      const record = await model.findByPk(id);
      if (!record) {
        return res.status(404).json({ error: "Registro no encontrado" });
      }
      res.json(record);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// UPDATE (PUT)
app.put(
  `${rutaPrincipal}/:connectionName/:modelName/:id`,
  validaTokenAuth,
  validateConnection,
  async (req, res) => {
    const { modelName, id } = req.params;
    const model = req.db.models[modelName];

    if (!model) {
      return res
        .status(404)
        .json({ error: `Modelo '${modelName}' no encontrado` });
    }

    try {
      /*if (modelName === 'productos') {
        const pros = await model.findAll();
       pros.forEach(element => {
         const codigoAleatorio = generarCodigoAleatorio();
          const idd = element.id;
          model.update({codigop: codigoAleatorio}, {
            where: { 'id':idd },
          });
        });
        const updatedRecord = await model.findByPk(id);
        return res.json(updatedRecord);        
      }*/
      //console.log("MODELO *** ", modelName);
      if (modelName === "configs") {
        const config = await model.findByPk(id);
        const upconfig = await config.update(req.body);
        const productos = await dataProductos(req.db.sequelize);
        if (config) {
          const modelp = req.db.models["productos"];
          productos.forEach((element) => {
            updateCostosPreciosProductos(
              element.costo * req.body.usd,
              req.body.usd,
              element.porcentaje,
              element.costo,
              element.id,
              modelp
            );
          });
        }
        return res.json(upconfig);
      }
      if (modelName === "compras") {
        const infoCompra = await model.findByPk(id);
        const modelPagar = req.db.models["cuentasxpagars"];
        const arrayPagar = {
          comprasid: id,
          proveedorid: infoCompra.proveedorid,
          fechacompra: infoCompra.fecha,
          totalcompra: infoCompra.total,
        };
        await modelPagar.create(arrayPagar);
      }
      if (modelName === "cuentasxpagars") {
        const infoPagar = await model.findByPk(id);
        const idpagar = infoPagar.comprasid;
        const modelCompra = req.db.models["compras"];
        const arrayCompra = {
          status: 2,
        };
        await modelCompra.update(arrayCompra, {
          where: { id: idpagar },
        });
      }
      if (modelName === "ventas") {
        const infoVenta = await model.findByPk(id);
        const modelCobrar = req.db.models["cuentasxcobrars"];
        const arrayCobrar = {
          ventasid: id,
          clienteid: infoVenta.clienteid,
          fechaventa: infoVenta.fecha,
          totalcobrar: infoVenta.total,
        };
        await modelCobrar.create(arrayCobrar);
      }
      if (modelName === "cuentasxcobrars") {
        const infoCobrar = await model.findByPk(id);
        const idcobrar = infoCobrar.ventasid;
        const modelVenta = req.db.models["ventas"];
        const arrayVenta = {
          status: 2,
        };
        await modelVenta.update(arrayVenta, {
          where: { id: idcobrar },
        });
      }
      const [updated] = await model.update(req.body, {
        where: { id },
      });
      if (updated) {
        const updatedRecord = await model.findByPk(id);
        res.json(updatedRecord);
      } else {
        res.status(404).json({ error: "Registro no encontrado" });
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// DELETE (DELETE)
app.delete(
  `${rutaPrincipal}/:connectionName/:modelName/:id`,
  validaTokenAuth,
  validateConnection,
  async (req, res) => {
    const { modelName, id } = req.params;
    const model = req.db.models[modelName];

    if (!model) {
      return res
        .status(404)
        .json({ error: `Modelo '${modelName}' no encontrado` });
    }

    try {
      if (modelName === "pedidos") {
        const records = await model.destroy({
          where: {
            clienteid: id,
          },
        });
        return res.json(records);
      }
      const deleted = await model.destroy({
        where: { id },
      });

      if (deleted) {
        res.json({ success: true, message: "Registro eliminado" });
      } else {
        res.status(404).json({ error: "Registro no encontrado" });
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.get(`${rutaPrincipal}/tasa`, async (req, res) => {
  const tasa = await scrapeBCV();
  return res.json(tasa);
});

// Sincronizar modelos con la base de datos y luego iniciar el servidor
sequelizeA
  .sync({ force: false }) // force: true borra y recrea las tablas
  .then(() => {
    console.log("Base de datos conectada");
    app.listen(PORT, () => {
      console.log(
        `Servidor corriendo en http://localhost:${PORT}${rutaPrincipal}`
      );
      //console.log(`API HTTPS escuchando en http://IP_PUBLICA:${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Error al conectar con la base de datos:", error);
  });
/*app.listen(PORT, () => {
  console.log(`API corriendo en http://localhost:${PORT}`);
});*/

async function Inventario(sequelize) {
  const resultado_productos = await dataProductos(sequelize);

  const [config, metadataconfig] = await sequelize.query(`
    SELECT usd FROM configs;
    `);

  const [cantidad_compras_producto, metadataccp] = await sequelize.query(`
    SELECT
	    COALESCE(SUM(t1.stock),0)+COALESCE(SUM(t2.cantidad),0) AS stockComprado,
	    (COALESCE(SUM(t1.stock),0)+COALESCE(SUM(t2.cantidad),0)) * t1.costo AS valorTotalDolares
    FROM productos t1, compras t2
    WHERE t1.id = t2.productoid
    GROUP BY t1.id;
    `);

  const stockComprado = cantidad_compras_producto.reduce(
    (accumulator, item) => {
      return (accumulator += parseInt(item.stockComprado));
    },
    0
  );

  const valorTotalDolares = cantidad_compras_producto.reduce(
    (accumulator, item) => {
      return (accumulator += parseFloat(item.valorTotalDolares));
    },
    0
  );

  let acumulador = 0;
  resultado_productos.forEach((item) => {
    if (item.stock === 1) {
      acumulador++;
    }
  });

  const [cantidad_ventas_producto, metadatacvp] = await sequelize.query(`
    SELECT COALESCE(SUM(TOTAL),0) AS totalvendido FROM ventas WHERE status != 0;
    `);

  const [cantidad_total_vendido, metadatactv] = await sequelize.query(`
    SELECT 
	    COALESCE(SUM(t2.cantidad ),0) AS canttotalvendido
    FROM ventasdetalles AS t2 
    LEFT JOIN ventas AS t1
    ON t2.ventaid = t1.id;
    `);

  const [cantidad_total_comprado, metadatactc] = await sequelize.query(`
    SELECT COALESCE(SUM(cantidad),0) AS canttotalcomprado	 FROM compras WHERE status != 0;
    `);

  const [retencion_iva, metadatarriva] = await sequelize.query(`
    SELECT COALESCE(SUM(iva),0) AS retencion
    FROM ventas 
    WHERE status = 1 OR status = 2;
    `);

  const [ganancia, metadatagan] = await sequelize.query(`
    SELECT
	    COALESCE(SUM(t2.cantidad * (t1.precioCompra * (t1.porcentaje/100))),0) AS ganancia
    FROM ventas t3, ventasdetalles t2, productos t1
    WHERE t3.status != 0 AND t2.ventaid = t3.id AND t2.productoid = t1.id;
      `);

  const [cuentasporcobrar, metadatacxc] = await sequelize.query(`
    SELECT
	    COALESCE(COUNT(id),0) AS cuentasporcobrar 
    FROM cuentasxcobrars 
    WHERE cuentasxcobrars.status = 0;
          `);

  const [cuentasporpagar, metadatacxp] = await sequelize.query(`
    SELECT
	    COALESCE(COUNT(id),0) AS cuentasporpagar
    FROM cuentasxpagars 
    WHERE cuentasxpagars.status = 0;
              `);

  if (resultado_productos) {
    const dataInventario = {
      productosTotales: resultado_productos.length,
      stockTotal: stockComprado,
      valorTotalCompraDolares: valorTotalDolares,
      valorTotalCompraBs: valorTotalDolares * config[0].usd,
      valorTotalVendidoBs: cantidad_ventas_producto[0].totalvendido,
      bajoStock: acumulador,
      cantidad_total_ventas: cantidad_total_vendido[0].canttotalvendido,
      cantidad_total_compras: cantidad_total_comprado[0].canttotalcomprado,
      retencion_iva: retencion_iva[0].retencion,
      ganancia: ganancia[0].ganancia,
      cuentasporcobrar: cuentasporcobrar[0].cuentasporcobrar,
      cuentasporpagar: cuentasporpagar[0].cuentasporpagar,
      resultado_productos: resultado_productos,
    };
    return dataInventario;
  } else {
    res.status(404).json({ message: "not found" });
  }
}

async function dataProductosModulo(sequelize) {
  const [cantidad_productos, metadatacp] = await sequelize.query(`
  SELECT
    t1.id,
    t1.codigop,
    t1.nombre,
    t1.categoriaid,
    t1.preciocompra,
    t1.precioventa,
    t1.stock AS stockant,
    COALESCE(t1.stock + SUM(t2.cantidad), t1.stock) - COALESCE((SELECT SUM(cantidad) FROM ventasdetalles WHERE productoid = t1.id ), 0) - COALESCE((SELECT SUM(cantidad) FROM pedidos WHERE productosid = t1.id), 0) AS stock,
    t1.imagen,
    t1.tasa,
    t1.costo,
    t1.porcentaje,
    t1.detalmayor,
    t1.fecha,
    t1.status,
    t1.exento
  FROM
    productos t1
  LEFT JOIN
    compras t2 ON t1.id = t2.productoid
  GROUP BY t1.id;
  `);

  return cantidad_productos;
}

async function dataProductos(sequelize) {
  const [cantidad_productos, metadatacp] = await sequelize.query(`
  SELECT
    t1.id,
    t1.codigop,
    t1.nombre,
    (SELECT nombre FROM categorias WHERE id = t1.categoriaid) AS categorias,
    t1.preciocompra,
    t1.precioventa,
    t1.stock AS stockAnt,
    COALESCE(t1.stock + SUM(t2.cantidad), t1.stock) - COALESCE((SELECT SUM(cantidad) FROM ventasdetalles WHERE productoid = t1.id ), 0) - COALESCE((SELECT SUM(cantidad) FROM pedidos WHERE productosid = t1.id), 0) AS stock,
    t1.imagen,
    t1.tasa,
    t1.costo,
    t1.porcentaje,
    t1.fecha,
    t1.status,
    t1.exento
  FROM
    productos t1
  LEFT JOIN
    compras t2 ON t1.id = t2.productoid
  GROUP BY t1.id;
  `);

  return cantidad_productos;
}

async function dataProductosVentas(sequelize) {
  const [cantidad_productos, metadatacp] = await sequelize.query(`
  SELECT
    t1.id,
    t1.codigop,
    t1.nombre,
    t1.precioventa,
    COALESCE(t1.stock + SUM(t2.cantidad), t1.stock) - COALESCE((SELECT SUM(cantidad) FROM ventasdetalles WHERE productoid = t1.id ), 0) - COALESCE((SELECT SUM(cantidad) FROM pedidos WHERE productosid = t1.id), 0) AS stock,
    t1.imagen,
    (t1.precioventa / t1.tasa) AS costo,
    t1.status,
    t1.exento
  FROM
    productos t1
  LEFT JOIN
    compras t2 ON t1.id = t2.productoid
  GROUP BY t1.id;
  `);

  return cantidad_productos;
}

async function updateCostosPreciosProductos(
  preciounitario,
  tasa,
  porcentaje,
  costo,
  productoid,
  modelp
) {
  modelp.update(
    {
      preciocompra: preciounitario,
      precioventa: preciounitario / (1 - porcentaje / 100),
      tasa: tasa,
      costo: costo,
    },
    {
      where: {
        id: productoid,
      },
    }
  );
}

const convert = (numero) => {
  let parteDecimal = String(numero).split(",")[1]; // "345"
  let primerosDosDecimales = parteDecimal.substring(0, 2);
  let valorCompleto = parseFloat(parseInt(numero) + "." + primerosDosDecimales);
  return valorCompleto;
};

async function scrapeBCV() {
  try {
    const response = await axios.get("https://www.bcv.org.ve", {
      httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    });
    const cheerio = require("cheerio");
    const $ = cheerio.load(response.data);
    return {
      usd: convert($("#dolar strong").text().trim()),
      eur: convert($("#euro strong").text().trim()),
      cny: convert($("#yuan strong").text().trim()),
    };
  } catch (error) {
    throw new Error("Scraping fallido: " + error.message);
  }
}

function generarCodigoAleatorio() {
  let codigo = "";
  for (let i = 0; i < 10; i++) {
    codigo += Math.floor(Math.random() * 10); // Genera un número aleatorio de 0 a 9
  }
  return codigo;
}
