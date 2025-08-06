// api/webhook.js - Vercel serverless function for TeleDiets integration

import { createHmac, timingSafeEqual } from 'crypto';

// Webhook verification function
function verifyShopifyWebhook(data, hmacHeader, secret) {
  if (!hmacHeader || !secret) return false;
  
  const calculatedHmac = createHmac('sha256', secret)
    .update(data, 'utf8')
    .digest('base64');
  
  return timingSafeEqual(
    Buffer.from(calculatedHmac),
    Buffer.from(hmacHeader)
  );
}

// Parse customer notes for health data
function parseCustomerNotes(notes) {
  if (!notes || !notes.includes('pat:')) {
    return null;
  }
  
  const data = {};
  
  // Extract Patient ID
  const patientIdMatch = notes.match(/pat:([a-f0-9-]+)/);
  data.patientId = patientIdMatch ? patientIdMatch[1] : null;
  
  // Extract health data
  const extractField = (fieldName) => {
    const regex = new RegExp(`${fieldName}:\\s*([^\\n]+)`);
    const match = notes.match(regex);
    return match ? match[1].trim() : null;
  };
  
  data.mobileNumber = extractField('mobile_number');
  data.zipCode = extractField('zip_code');
  data.dateOfBirth = extractField('date_of_birth');
  data.gender = extractField('gender');
  
  return data;
}

// Convert date from MM/DD/YYYY to ISO format
function convertDateToISO(dateStr) {
  if (!dateStr) return '1990-01-01T00:00:00.000Z';
  
  const parts = dateStr.split('/');
  if (parts.length !== 3) return '1990-01-01T00:00:00.000Z';
  
  const month = parts[0].padStart(2, '0');
  const day = parts[1].padStart(2, '0');
  const year = parts[2];
  
  return `${year}-${month}-${day}T00:00:00.000Z`;
}

// Generate random password
function generatePassword(length = 8) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let password = '';
  for (let i = 0; i < length; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return password;
}

// TeleDiets API Authentication
async function authenticateTeleDiets() {
  const authPayload = {
    Username: "amit-kuma6",
    Password: "$p$bb6kuue"
  };
  
  try {
    const response = await fetch('https://api.dmwebpro.com/Authentication/CompanyLogin', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(authPayload)
    });
    
    const authData = await response.json();
    
    if (authData.Status === 'Success') {
      return {
        authToken: authData.Data.AuthToken,
        companyId: authData.Data.JsonClaimData.CompanyID
      };
    } else {
      throw new Error(`Authentication failed: ${authData.Message}`);
    }
  } catch (error) {
    console.error('TeleDiets authentication error:', error);
    throw error;
  }
}

// Create TeleDiets user account
async function createTeleDietsUser(customerData, authToken, companyId) {
  const password = generatePassword();
  
  const userPayload = {
    CompanyID: companyId,
    Username: customerData.email,
    Password: password,
    FirstName: customerData.firstName,
    LastName: customerData.lastName,
    Email: customerData.email,
    BirthDate: convertDateToISO(customerData.dateOfBirth),
    Gender: customerData.gender === 'female' ? 1 : 0,
    Height: 66, // Default 5'6"
    Weight: 150, // Default 150 lbs
    WeightGoals: 1, // Maintain weight
    BodyType: 1, // Type II
    Profession: 1, // Moderate activity
    GeneralUnits: 0, // US units
    BMRCalcMethod: 0 // Default calculation
  };
  
  try {
    const response = await fetch('https://api.dmwebpro.com/CompanyUser/AddUserProfile', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`
      },
      body: JSON.stringify(userPayload)
    });
    
    const result = await response.json();
    
    if (result.Status === 'Success') {
      return {
        userId: result.Data.UserID,
        username: customerData.email,
        password: password
      };
    } else {
      throw new Error(`User creation failed: ${result.Message}`);
    }
  } catch (error) {
    console.error('TeleDiets user creation error:', error);
    throw error;
  }
}

// Update Shopify customer metafields
async function updateCustomerMetafields(customerId, teleDietsData, shopifyAccessToken, shopDomain) {
  const metafields = [
    {
      namespace: 'custom',
      key: 'telediets_user_id',
      value: teleDietsData.userId.toString(),
      type: 'single_line_text_field'
    },
    {
      namespace: 'custom', 
      key: 'telediets_username',
      value: teleDietsData.username,
      type: 'single_line_text_field'
    },
    {
      namespace: 'custom',
      key: 'telediets_password', 
      value: teleDietsData.password,
      type: 'single_line_text_field'
    },
    {
      namespace: 'custom',
      key: 'telediets_created_date',
      value: new Date().toISOString(),
      type: 'date_time'
    },
    {
      namespace: 'custom',
      key: 'telediets_status',
      value: 'created',
      type: 'single_line_text_field'
    }
  ];
  
  for (const metafield of metafields) {
    try {
      const response = await fetch(`https://${shopDomain}/admin/api/2023-10/customers/${customerId}/metafields.json`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': shopifyAccessToken
        },
        body: JSON.stringify({ metafield })
      });
      
      if (!response.ok) {
        console.error(`Failed to create metafield ${metafield.key}:`, response.statusText);
      }
    } catch (error) {
      console.error(`Error creating metafield ${metafield.key}:`, error);
    }
  }
}

// Log error to customer metafield
async function logErrorToCustomer(customerId, errorMessage, shopifyAccessToken, shopDomain) {
  try {
    const errorMetafield = {
      namespace: 'custom',
      key: 'telediets_error',
      value: errorMessage,
      type: 'multi_line_text_field'
    };
    
    const statusMetafield = {
      namespace: 'custom',
      key: 'telediets_status',
      value: 'error',
      type: 'single_line_text_field'
    };
    
    await Promise.all([
      fetch(`https://${shopDomain}/admin/api/2023-10/customers/${customerId}/metafields.json`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': shopifyAccessToken
        },
        body: JSON.stringify({ metafield: errorMetafield })
      }),
      fetch(`https://${shopDomain}/admin/api/2023-10/customers/${customerId}/metafields.json`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': shopifyAccessToken
        },
        body: JSON.stringify({ metafield: statusMetafield })
      })
    ]);
  } catch (logError) {
    console.error('Failed to log error to customer metafield:', logError);
  }
}

// Main webhook handler - Vercel serverless function
export default async function handler(req, res) {
  // Only allow POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  
  try {
    // Get environment variables
    const webhookSecret = process.env.SHOPIFY_WEBHOOK_SECRET;
    const shopifyAccessToken = process.env.SHOPIFY_ACCESS_TOKEN;
    const shopDomain = process.env.SHOP_DOMAIN;
    
    if (!webhookSecret || !shopifyAccessToken || !shopDomain) {
      console.error('Missing environment variables');
      return res.status(500).json({ error: 'Server configuration error' });
    }
    
    // Verify webhook authenticity
    const hmacHeader = req.headers['x-shopify-hmac-sha256'];
    const body = JSON.stringify(req.body);
    
    if (!verifyShopifyWebhook(body, hmacHeader, webhookSecret)) {
      console.error('Webhook verification failed');
      return res.status(401).json({ error: 'Unauthorized webhook' });
    }
    
    const customer = req.body;
    console.log(`Processing customer: ${customer.email} (ID: ${customer.id})`);
    
    // Check if customer has health data
    const healthData = parseCustomerNotes(customer.note);
    if (!healthData || !healthData.patientId) {
      console.log('No health data found, skipping TeleDiets creation');
      return res.status(200).json({ message: 'No health data found, skipping TeleDiets creation' });
    }
    
    console.log('Health data found, creating TeleDiets account');
    
    // Check if TeleDiets account already exists
    const existingTeleDietsId = customer.metafields?.find(
      m => m.namespace === 'custom' && m.key === 'telediets_user_id'
    );
    
    if (existingTeleDietsId) {
      console.log('TeleDiets account already exists');
      return res.status(200).json({ message: 'TeleDiets account already exists' });
    }
    
    // Authenticate with TeleDiets
    const { authToken, companyId } = await authenticateTeleDiets();
    console.log('TeleDiets authentication successful');
    
    // Prepare customer data
    const customerData = {
      email: customer.email,
      firstName: customer.first_name,
      lastName: customer.last_name,
      dateOfBirth: healthData.dateOfBirth,
      gender: healthData.gender
    };
    
    // Create TeleDiets user
    const teleDietsData = await createTeleDietsUser(customerData, authToken, companyId);
    console.log(`TeleDiets user created with ID: ${teleDietsData.userId}`);
    
    // Update Shopify customer with TeleDiets credentials
    await updateCustomerMetafields(
      customer.id,
      teleDietsData,
      shopifyAccessToken,
      shopDomain
    );
    
    console.log(`Successfully created TeleDiets account for customer ${customer.email}`);
    
    return res.status(200).json({
      message: 'TeleDiets account created successfully',
      teleDietsUserId: teleDietsData.userId
    });
    
  } catch (error) {
    console.error('Webhook processing error:', error);
    
    // Log error to customer metafield for debugging
    if (req.body?.id) {
      try {
        await logErrorToCustomer(
          req.body.id,
          `Error: ${error.message}\nTime: ${new Date().toISOString()}`,
          process.env.SHOPIFY_ACCESS_TOKEN,
          process.env.SHOP_DOMAIN
        );
      } catch (metafieldError) {
        console.error('Failed to log error to customer metafield:', metafieldError);
      }
    }
    
    return res.status(500).json({ 
      error: 'Internal server error',
      message: error.message 
    });
  }
}