/**
 * check-models.js - Run this to see available Gemini models
 * 
 * Usage: node check-models.js
 */

require('dotenv').config();
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

async function listAvailableModels() {
  if (!GEMINI_API_KEY) {
    console.error('❌ GEMINI_API_KEY not found in .env file');
    console.log('\nPlease add your API key to .env:');
    console.log('GEMINI_API_KEY=your_key_here');
    return;
  }

  console.log('🔍 Checking available Gemini models...\n');

  try {
    // Check v1 API
    console.log('📡 Checking v1 API...');
    const v1Response = await fetch(
      `https://generativelanguage.googleapis.com/v1/models?key=${GEMINI_API_KEY}`
    );

    if (v1Response.ok) {
      const v1Data = await v1Response.json();
      console.log('✅ v1 API - Available models:');
      
      if (v1Data.models && v1Data.models.length > 0) {
        v1Data.models.forEach(model => {
          const supportsGenerate = model.supportedGenerationMethods?.includes('generateContent');
          console.log(`  ${supportsGenerate ? '✓' : '✗'} ${model.name}`);
        });
      } else {
        console.log('  No models found');
      }
    } else {
      const errorText = await v1Response.text();
      console.log(`❌ v1 API Error (${v1Response.status}):`, errorText.substring(0, 200));
    }

    console.log('\n📡 Checking v1beta API...');
    const v1betaResponse = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models?key=${GEMINI_API_KEY}`
    );

    if (v1betaResponse.ok) {
      const v1betaData = await v1betaResponse.json();
      console.log('✅ v1beta API - Available models:');
      
      if (v1betaData.models && v1betaData.models.length > 0) {
        v1betaData.models.forEach(model => {
          const supportsGenerate = model.supportedGenerationMethods?.includes('generateContent');
          console.log(`  ${supportsGenerate ? '✓' : '✗'} ${model.name}`);
        });
      } else {
        console.log('  No models found');
      }
    } else {
      const errorText = await v1betaResponse.text();
      console.log(`❌ v1beta API Error (${v1betaResponse.status}):`, errorText.substring(0, 200));
    }

    // Test a simple generation
    console.log('\n🧪 Testing generation with gemini-1.5-flash-latest...');
    const testResponse = await fetch(
      `https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash-latest:generateContent?key=${GEMINI_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: 'Say hello in 3 words' }] }]
        })
      }
    );

    if (testResponse.ok) {
      const testData = await testResponse.json();
      const result = testData.candidates?.[0]?.content?.parts?.[0]?.text;
      console.log('✅ Generation test successful!');
      console.log(`   Response: "${result}"`);
    } else {
      const errorText = await testResponse.text();
      console.log('❌ Generation test failed:', errorText.substring(0, 300));
    }

    // Recommendations
    console.log('\n📋 RECOMMENDED CONFIGURATION:');
    console.log('Add this to your .env file:');
    console.log('─────────────────────────────────────');
    console.log('GEMINI_API_KEY=your_key_here');
    console.log('GEMINI_MODEL=gemini-1.5-flash-latest');
    console.log('─────────────────────────────────────');

  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

listAvailableModels();