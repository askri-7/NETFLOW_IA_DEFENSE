import { Component } from '@angular/core';
import { AlertsPannel } from "./alerts-pannel/alerts-pannel";
import { FlowsPannel } from './flows-pannel/flows-pannel';
import { StatsPannel } from './stats-pannel/stats-pannel';
import { NetGraph } from './net-graph/net-graph';

@Component({
  selector: 'app-dash-board',
  imports: [
    AlertsPannel,
    FlowsPannel,
    StatsPannel,
    NetGraph
  ],
  templateUrl: './dash-board.html',
  styleUrl: './dash-board.css',
})
export class DashBoard {

}
