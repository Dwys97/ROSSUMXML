const bcrypt = require('bcrypt');

const hash = '$2b$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGQRxYxv5ZSXlAkN3Vj6zO6';
const password = 'password123';

bcrypt.compare(password, hash).then(result => {
  console.log('Password match:', result);
  if (!result) {
    console.log('Generating new hash...');
    bcrypt.hash(password, 10).then(newHash => {
      console.log('New hash:', newHash);
    });
  }
});
