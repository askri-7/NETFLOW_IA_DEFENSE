import { Component, signal } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { Navbar } from './navbar/navbar';
import { DashBoard } from './dash-board/dash-board';

@Component({
  selector: 'app-root',
  imports: [
    RouterOutlet,
    Navbar,
    DashBoard
  ],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App {
  protected readonly title = signal('Projet ossec');
}
