<?php

namespace Database\Seeders;

use App\Models\User;
use Faker\Factory;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

class UserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        $faker = Factory::create();
        $user = User::create([
            'name' => $faker->name(),
            'email' => 'admin@admin.com',
            'password' => Hash::make('1234567890'),
        ]);
        // display message
        $this->command->info('User Created');
    }
}
